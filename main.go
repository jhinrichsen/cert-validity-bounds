// Check certificate validity bounds
// Return codes:
//      1: wrong usage (commandline arguments)
//      2: at least one certificate in chain about to expire
//      3: at least one certificate in chain expired

package main

import (
        "crypto/tls"
        "flag"
        "fmt"
        "log"
        "math"
        "os"
        "time"
)

const (
        RC_OK     = 0
        RC_USAGE  = 1
        RC_YELLOW = 2
        RC_RED    = 3
)

func days(t time.Time) int {
        return int(math.Round(time.Since(t).Hours() / 24))
}

func main() {
        insecure := flag.Bool("insecure", true, "Allow custom cert path")
        yellow := flag.Int("yellow", 30,
                "number of days to show as about to expire")
        red := flag.Int("red", -1,
                "number of days to show as expired")
        flag.Parse()
        flag.Usage = func() {
                fmt.Fprintf(os.Stderr, "Usage: %s [host[:port]]...\n",
                        os.Args[0])
        }
        if flag.NArg() == 0 {
                flag.Usage()
                os.Exit(1)
        }

        // Fetch remote cert
        now := time.Now()
        log.Printf("Comparing certificate validity bounds against %s\n", now)
        isRed := false
        isYellow := false
        for _, addr := range flag.Args() {
                var cfg tls.Config
                if *insecure {
                        cfg.InsecureSkipVerify = true
                }
                conn, err := tls.Dial("tcp", addr, &cfg)
                if err != nil {
                        log.Fatal(err)
                }
                conn.Handshake()
                certs := conn.ConnectionState().PeerCertificates
                log.Printf("%s: %d certs\n", addr, len(certs))
                for _, c := range certs {
                        log.Printf("--------------------------------------\n")
                        log.Printf("Issuer: %+v\n", c.Issuer)
                        log.Printf("NotBefore: %+v\n", c.NotBefore)
                        log.Printf("NotAfter: %+v\n", c.NotAfter)
                        d1 := days(c.NotBefore)
                        log.Printf("Valid since: %+v days\n",
                                d1)
                        d2 := -days(c.NotAfter)
                        log.Printf("Valid for: %+v days\n",
                                d2)
                        if d2 < *red {
                                isRed = true
                        }
                        if d2 < *yellow {
                                isYellow = true
                        }
                }
        }
        // RED overrides YELLOW
        if isRed {
                os.Exit(RC_RED)
        }
        if isYellow {
                os.Exit(RC_YELLOW)
        }
}
