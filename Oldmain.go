package main

// import (
// 	"bytes"
// 	"encoding/binary"
// 	"errors"
// 	"flag"
// 	"fmt"
// 	"log"
// 	"os"
// 	"os/signal"
// 	"strings"
// 	"syscall"

// 	"github.com/cilium/ebpf"
// 	"github.com/cilium/ebpf/link"
// 	"github.com/cilium/ebpf/perf"
// 	"github.com/cilium/ebpf/rlimit"
// 	"go.uber.org/zap"
// )

// var objs = bpfObjects{}

// // $BPF_CLANG and $BPF_CFLAGS are set by the Makefile.
// //go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc $BPF_CLANG -cflags $BPF_CFLAGS -no-global-types -target $TARGET bpf ssl.c -- -I./headers -I./headers/$TARGET

// func getlogger() *zap.Logger {
// 	// logger init
// 	logCfg := zap.NewDevelopmentConfig()
// 	logCfg.Level = zap.NewAtomicLevelAt(zap.InfoLevel)
// 	logger, err := logCfg.Build()
// 	if err != nil {
// 		log.Panic("failed to start the logger for the CLI")
// 		return nil
// 	}
// 	return logger
// }

// type MasterSecretEvent struct {
// 	// TLS 1.2
// 	Version      int32    `json:"version"`      // TLS Version
// 	ClientRandom [32]byte `json:"clientRandom"` // Client Random
// 	MasterKey    [48]byte `json:"masterKey"`    // Master Key

// 	// TLS 1.3
// 	CipherId               uint32   `json:"cipherId"`               // cipher ID
// 	HandshakeSecret        [64]byte `json:"handshakeSecret"`        // Handshake Secret
// 	HandshakeTrafficHash   [64]byte `json:"handshakeTrafficHash"`   // Handshake Traffic hash
// 	ClientAppTrafficSecret [64]byte `json:"clientAppTrafficSecret"` // Client App Traffic Secret
// 	ServerAppTrafficSecret [64]byte `json:"serverAppTrafficSecret"` // Server App Traffic Secret
// 	ExporterMasterSecret   [64]byte `json:"exporterMasterSecret"`   // Exporter Master Secret
// }

// func main() {

// 	fmt.Println("Ebpf Loader PID:", os.Getpid())

// 	stopper := make(chan os.Signal, 1)
// 	signal.Notify(stopper, os.Interrupt, syscall.SIGHUP, syscall.SIGINT, syscall.SIGQUIT, syscall.SIGTERM)

// 	// Allow the current process to lock memory for eBPF resources.
// 	if err := rlimit.RemoveMemlock(); err != nil {
// 		log.Fatal(err)
// 	}

// 	logger := getlogger()
// 	defer logger.Sync()

// 	// Load pre-compiled programs and maps into the kernel.
// 	// objs := bpfObjects{}
// 	if err := loadBpfObjects(&objs, nil); err != nil {
// 		var ve *ebpf.VerifierError
// 		if errors.As(err, &ve) {
// 			errString := strings.Join(ve.Log, "\n")
// 			logger.Error("verifier log: ", zap.String("err", errString))
// 		}
// 		logger.Error("failed to load eBPF objects", zap.Error(err))
// 		return
// 	}

// 	defer objs.Close()

// 	const libsslPath = "/usr/lib/aarch64-linux-gnu/libssl.so.3"

// 	// Open a uprobe and a uretprobe at the entry of the SSL_do_handshake symbol from OpenSSL
// 	ex, err := link.OpenExecutable(libsslPath)
// 	if err != nil {
// 		logger.Error("failed to open the libssl shared object", zap.Error(err))
// 	}
// 	ssldh, err := ex.Uprobe("SSL_do_handshake", objs.UprobeSslDoHandshake, nil)
// 	if err != nil {
// 		logger.Error("failed to attach the uprobe hook on SSL_do_handshake", zap.Error(err))
// 	}
// 	ssldhret, err := ex.Uretprobe("SSL_do_handshake", objs.UretprobeSslDoHandshake, nil)
// 	if err != nil {
// 		logger.Error("failed to attach the uretprobe hook on SSL_do_handshake", zap.Error(err))
// 	}

// 	defer ssldh.Close()
// 	defer ssldhret.Close()

// 	var appPidFlag int
// 	flag.IntVar(&appPidFlag, "pid", 0, "Application PID")
// 	flag.Parse()
// 	appPid := uint32(appPidFlag)

// 	key := 0
// 	//send application pid to kernel to filter.
// 	log.Printf("Application pid sending to kernel:%v", appPid)
// 	err = objs.AppPidMap.Update(uint32(key), &appPid, ebpf.UpdateAny)
// 	if err != nil {
// 		log.Fatalf("failed to send application pid to kernel %v", err)
// 	}

// 	log.Printf("Probes added to the kernel.\n")

// 	rd, err := perf.NewReader(objs.MastersecretEvents, os.Getpagesize())
// 	if err != nil {
// 		log.Fatalf("creating perf event reader: %s", err)
// 	}
// 	defer rd.Close()

// 	go func() {
// 		var event MasterSecretEvent
// 		for {
// 			record, err := rd.Read()
// 			if err != nil {
// 				if errors.Is(err, perf.ErrClosed) {
// 					return
// 				}
// 				log.Printf("reading from perf event reader: %s", err)
// 				continue
// 			}

// 			if record.LostSamples != 0 {
// 				log.Printf("perf event ring buffer full, dropped %d samples", record.LostSamples)
// 				continue
// 			}

// 			// Parse the perf event entry into a bpfEvent structure.
// 			if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &event); err != nil {
// 				log.Printf("parsing perf event: %s", err)
// 				continue
// 			}
// 			fmt.Printf("Master Event || version:%v\n", event.Version)
// 			fmt.Printf("Master Event || clientRandom:%2x\n", event.ClientRandom)
// 			fmt.Printf("Master Event || masterKey:%2x\n", event.MasterKey)
// 			fmt.Printf("Master Event || cipherId:%v\n", event.CipherId)
// 			fmt.Printf("Master Event || handshakeSecret:%2x\n", event.HandshakeSecret)
// 			fmt.Printf("Master Event || handshakeTrafficHash:%2x\n", event.HandshakeTrafficHash)
// 			fmt.Printf("Master Event || clientAppTrafficSecret:%2x\n", event.ClientAppTrafficSecret)
// 			fmt.Printf("Master Event || serverAppTrafficSecret:%2x\n", event.ServerAppTrafficSecret)
// 			fmt.Printf("Master Event || exporter Master Secret:%2x\n", event.ExporterMasterSecret)
// 		}
// 	}()

// 	<-stopper
// 	log.Println("Received signal, exiting program..")

// }
