package main

import (
	"bytes"
	"crypto"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
	"github.com/cilium/ebpf/rlimit"
	"golang.org/x/crypto/hkdf"
	"go.uber.org/zap"
)

var objs = bpfObjects{}

const (
	KeyLogLabelTLS12           = "CLIENT_RANDOM"
	KeyLogLabelClientHandshake = "CLIENT_HANDSHAKE_TRAFFIC_SECRET"
	KeyLogLabelServerHandshake = "SERVER_HANDSHAKE_TRAFFIC_SECRET"
	KeyLogLabelClientTraffic   = "CLIENT_TRAFFIC_SECRET_0"
	KeyLogLabelServerTraffic   = "SERVER_TRAFFIC_SECRET_0"
	KeyLogLabelExporterSecret  = "EXPORTER_SECRET"

	TlsAes128GcmSha256        uint16 = 0x1301
	TlsAes256GcmSha384        uint16 = 0x1302
	TlsChacha20Poly1305Sha256 uint16 = 0x1303
)

type MasterSecretEvent struct {
	Version      int32
	ClientRandom [32]byte
	MasterKey    [48]byte

	CipherId               uint32
	HandshakeSecret        [64]byte
	HandshakeTrafficHash   [64]byte
	ClientAppTrafficSecret [64]byte
	ServerAppTrafficSecret [64]byte
	ExporterMasterSecret   [64]byte
}

type MasterKeyLogger struct {
	keylogger  *os.File
	masterKeys sync.Map // To prevent writing duplicate secrets
}

func NewMasterKeyLogger(filename string) (*MasterKeyLogger, error) {
	file, err := os.OpenFile(filename, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		return nil, fmt.Errorf("failed to open keylog file: %v", err)
	}
	return &MasterKeyLogger{keylogger: file}, nil
}

func (m *MasterKeyLogger) Close() error {
	return m.keylogger.Close()
}

func (m *MasterKeyLogger) saveMasterSecret(secretEvent *MasterSecretEvent) {
	clientRandom := fmt.Sprintf("%02x", secretEvent.ClientRandom[:])

	if _, exists := m.masterKeys.Load(clientRandom); exists {
		return // Secret already exists, no need to write again
	}

	var b bytes.Buffer

	if secretEvent.Version < 0x0304 {
		// TLS 1.2
		masterKey := fmt.Sprintf("%02x", secretEvent.MasterKey[:])
		b.WriteString(fmt.Sprintf("%s %s %s\n", KeyLogLabelTLS12, clientRandom, masterKey))
		m.masterKeys.Store(clientRandom, true)
	} else {
		// TLS 1.3
		length := 32
		transcript := crypto.SHA256

		switch uint16(secretEvent.CipherId & 0xFFFF) {
		case TlsAes128GcmSha256, TlsChacha20Poly1305Sha256:
			length = 32
			transcript = crypto.SHA256
		case TlsAes256GcmSha384:
			length = 48
			transcript = crypto.SHA384
		}

		clientHandshakeSecret := ExpandLabel(secretEvent.HandshakeSecret[:length], KeyLogLabelClientHandshake, secretEvent.HandshakeTrafficHash[:length], length, transcript)
		serverHandshakeSecret := ExpandLabel(secretEvent.HandshakeSecret[:length], KeyLogLabelServerHandshake, secretEvent.HandshakeTrafficHash[:length], length, transcript)

		b.WriteString(fmt.Sprintf("%s %s %02x\n", KeyLogLabelClientHandshake, clientRandom, clientHandshakeSecret))
		b.WriteString(fmt.Sprintf("%s %s %02x\n", KeyLogLabelServerHandshake, clientRandom, serverHandshakeSecret))
		b.WriteString(fmt.Sprintf("%s %s %02x\n", KeyLogLabelClientTraffic, clientRandom, secretEvent.ClientAppTrafficSecret[:length]))
		b.WriteString(fmt.Sprintf("%s %s %02x\n", KeyLogLabelServerTraffic, clientRandom, secretEvent.ServerAppTrafficSecret[:length]))
		b.WriteString(fmt.Sprintf("%s %s %02x\n", KeyLogLabelExporterSecret, clientRandom, secretEvent.ExporterMasterSecret[:length]))

		m.masterKeys.Store(clientRandom, true)
	}

	_, err := m.keylogger.Write(b.Bytes())
	if err != nil {
		fmt.Printf("failed to write keylog: %v\n", err)
	}
}

func ExpandLabel(secret []byte, label string, context []byte, length int, transcript crypto.Hash) []byte {
	var hkdfLabel bytes.Buffer
	hkdfLabel.WriteByte(byte(length >> 8))
	hkdfLabel.WriteByte(byte(length))

	hkdfLabel.WriteByte(byte(len("tls13 " + label)))
	hkdfLabel.WriteString("tls13 ")
	hkdfLabel.WriteString(label)

	hkdfLabel.WriteByte(byte(len(context)))
	hkdfLabel.Write(context)

	out := make([]byte, length)
	hkdfExpand := hkdf.Expand(transcript.New, secret, hkdfLabel.Bytes())
	_, err := hkdfExpand.Read(out)
	if err != nil {
		panic("HKDF-Expand-Label failed")
	}
	return out
}

func getLogger() *zap.Logger {
	logCfg := zap.NewDevelopmentConfig()
	logCfg.Level = zap.NewAtomicLevelAt(zap.InfoLevel)
	logger, err := logCfg.Build()
	if err != nil {
		log.Panic("failed to start the logger for the CLI")
		return nil
	}
	return logger
}

func main() {
	fmt.Println("Ebpf Loader PID:", os.Getpid())

	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGHUP, syscall.SIGINT, syscall.SIGQUIT, syscall.SIGTERM)

	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}

	logger := getLogger()
	defer logger.Sync()

	if err := loadBpfObjects(&objs, nil); err != nil {
		var ve *ebpf.VerifierError
		if errors.As(err, &ve) {
			errString := strings.Join(ve.Log, "\n")
			logger.Error("verifier log: ", zap.String("err", errString))
		}
		logger.Error("failed to load eBPF objects", zap.Error(err))
		return
	}
	defer objs.Close()

	const libsslPath = "/usr/lib/aarch64-linux-gnu/libssl.so.3"

	ex, err := link.OpenExecutable(libsslPath)
	if err != nil {
		logger.Error("failed to open the libssl shared object", zap.Error(err))
	}
	ssldh, err := ex.Uprobe("SSL_do_handshake", objs.UprobeSslDoHandshake, nil)
	if err != nil {
		logger.Error("failed to attach the uprobe hook on SSL_do_handshake", zap.Error(err))
	}
	ssldhret, err := ex.Uretprobe("SSL_do_handshake", objs.UretprobeSslDoHandshake, nil)
	if err != nil {
		logger.Error("failed to attach the uretprobe hook on SSL_do_handshake", zap.Error(err))
	}
	defer ssldh.Close()
	defer ssldhret.Close()

	var appPidFlag int
	flag.IntVar(&appPidFlag, "pid", 0, "Application PID")
	flag.Parse()
	appPid := uint32(appPidFlag)

	key := 0
	log.Printf("Application pid sending to kernel: %v", appPid)
	err = objs.AppPidMap.Update(uint32(key), &appPid, ebpf.UpdateAny)
	if err != nil {
		log.Fatalf("failed to send application pid to kernel %v", err)
	}

	keyLogger, err := NewMasterKeyLogger("openssl_key.log")
	if err != nil {
		log.Fatalf("failed to initialize keylogger: %v", err)
	}
	defer keyLogger.Close()

	log.Printf("Probes added to the kernel.\n")

	rd, err := perf.NewReader(objs.MastersecretEvents, os.Getpagesize())
	if err != nil {
		log.Fatalf("creating perf event reader: %s", err)
	}
	defer rd.Close()

	go func() {
		var event MasterSecretEvent
		for {
			record, err := rd.Read()
			if err != nil {
				if errors.Is(err, perf.ErrClosed) {
					return
				}
				log.Printf("reading from perf event reader: %s", err)
				continue
			}

			if record.LostSamples != 0 {
				log.Printf("perf event ring buffer full, dropped %d samples", record.LostSamples)
				continue
			}

			if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &event); err != nil {
				log.Printf("parsing perf event: %s", err)
				continue
			}

			keyLogger.saveMasterSecret(&event)
		}
	}()

	<-stopper
	log.Println("Received signal, exiting program..")
}