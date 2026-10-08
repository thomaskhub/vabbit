package adminlogin

import (
	"errors"
	"fmt"
	"io"
	"os"
	"runtime"
	"unicode/utf8"

	"golang.org/x/term"
)

// PasswordEnv lets scripts supply the master password without a terminal.
const PasswordEnv = "VABBIT_ADMIN_PASSWORD"

// MinPasswordLen is the shortest master password accepted for a new file.
const MinPasswordLen = 8

// ErrInterrupted is returned when the user presses Ctrl-C at a prompt.
var ErrInterrupted = errors.New("interrupted")

// Password asks for the master password of an existing login file.
func Password() ([]byte, error) {
	if pw := os.Getenv(PasswordEnv); pw != "" {
		return []byte(pw), nil
	}
	pw, err := Prompt("Master password: ")
	return []byte(pw), err
}

// NewPassword asks for a new master password twice.
func NewPassword() ([]byte, error) {
	if pw := os.Getenv(PasswordEnv); pw != "" {
		return []byte(pw), nil
	}
	fmt.Fprintln(os.Stderr, "Choose a master password. It encrypts your admin tokens on this machine and")
	fmt.Fprintln(os.Stderr, "can't be recovered; without it you need `vabbit deploy rotate-admin`.")
	pw, err := Prompt("New master password: ")
	if err != nil {
		return nil, err
	}
	if utf8.RuneCountInString(pw) < MinPasswordLen {
		return nil, fmt.Errorf("the master password needs at least %d characters", MinPasswordLen)
	}
	again, err := Prompt("Repeat master password: ")
	if err != nil {
		return nil, err
	}
	if again != pw {
		return nil, errors.New("the passwords don't match")
	}
	return []byte(pw), nil
}

// Prompt reads a secret from the terminal, showing * for each character.
func Prompt(prompt string) (string, error) {
	in, out, err := openTerminal()
	if err != nil {
		return "", fmt.Errorf("no terminal to ask for the master password; set %s", PasswordEnv)
	}
	defer in.Close()
	defer out.Close()
	fd := int(in.Fd())
	old, err := term.MakeRaw(fd)
	if err != nil {
		return "", fmt.Errorf("no terminal to ask for the master password; set %s", PasswordEnv)
	}
	defer term.Restore(fd, old)
	fmt.Fprint(out, prompt)
	return ReadMasked(in, out)
}

// ReadMasked reads a line from a terminal in raw mode, echoing * per
// character. Backspace deletes, Ctrl-U clears, Ctrl-C aborts.
func ReadMasked(r io.Reader, w io.Writer) (string, error) {
	var buf []byte
	b := make([]byte, 1)
	for {
		if _, err := r.Read(b); err != nil {
			fmt.Fprint(w, "\r\n")
			if err == io.EOF && len(buf) > 0 {
				return string(buf), nil
			}
			return "", err
		}
		switch c := b[0]; {
		case c == '\r' || c == '\n':
			fmt.Fprint(w, "\r\n")
			return string(buf), nil
		case c == 3: // Ctrl-C
			fmt.Fprint(w, "\r\n")
			return "", ErrInterrupted
		case c == 4 && len(buf) == 0: // Ctrl-D
			fmt.Fprint(w, "\r\n")
			return "", io.EOF
		case c == 127 || c == 8: // Backspace
			if len(buf) > 0 {
				_, size := utf8.DecodeLastRune(buf)
				buf = buf[:len(buf)-size]
				fmt.Fprint(w, "\b \b")
			}
		case c == 21: // Ctrl-U
			for n := utf8.RuneCount(buf); n > 0; n-- {
				fmt.Fprint(w, "\b \b")
			}
			buf = buf[:0]
		case c < 32:
			// Ignore other control characters (and escape sequences' first byte).
		default:
			buf = append(buf, c)
			if c&0xC0 != 0x80 { // one * per character, not per UTF-8 byte
				fmt.Fprint(w, "*")
			}
		}
	}
}

// openTerminal opens the controlling terminal for reading and writing:
// /dev/tty, or the console (CONIN$ and CONOUT$) on Windows.
func openTerminal() (in, out *os.File, err error) {
	if runtime.GOOS == "windows" {
		if in, err = os.OpenFile("CONIN$", os.O_RDWR, 0); err != nil {
			return nil, nil, err
		}
		if out, err = os.OpenFile("CONOUT$", os.O_RDWR, 0); err != nil {
			in.Close()
			return nil, nil, err
		}
		return in, out, nil
	}
	if in, err = os.OpenFile("/dev/tty", os.O_RDWR, 0); err != nil {
		return nil, nil, err
	}
	if out, err = os.OpenFile("/dev/tty", os.O_RDWR, 0); err != nil {
		in.Close()
		return nil, nil, err
	}
	return in, out, nil
}
