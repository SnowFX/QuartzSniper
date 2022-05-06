package utils

import (
	"bufio"
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"github.com/gookit/color"
	. "github.com/logrusorgru/aurora"
	"io"
	"math/rand"
	"net/url"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"strings"
	"time"
)

var (
	clear     map[string]func()
	debug *os.File
	Banner =
		`
________                       __            _________      .__                     
\_____  \  __ _______ ________/  |_________ /   _____/ ____ |__|_____   ___________ 
 /  / \  \|  |  \__  \\_  __ \   __\___   / \_____  \ /    \|  \____ \_/ __ \_  __ \
/   \_/.  \  |  // __ \|  | \/|  |  /    /  /        \   |  \  |  |_> >  ___/|  | \/
\_____\ \_/____/(____  /__|   |__| /_____ \/_______  /___|  /__|   __/ \___  >__|   
       \__>          \/                  \/        \/     \/   |__|        \/       
	
	`
)

func init() {
	clear = make(map[string]func()) //Initialize it
	clear["linux"] = func() {
		cmd := exec.Command("clear") //Linux example, its tested
		cmd.Stdout = os.Stdout
		cmd.Run()
	}
	clear["windows"] = func() {
		cmd := exec.Command("cmd", "/c", "cls") //Windows example, its tested
		cmd.Stdout = os.Stdout
		cmd.Run()
	}
	if runtime.GOOS == "linux" {
		debug, _ = os.Create("debug.txt")
	}
}

func LogInfo(msg string) {
	fmt.Printf("\t[%s] [%s] ~> %s\r\n", Magenta(time.Now().Format("15:04:05")), Cyan("II"), msg)
}
func LogWarn(msg string) {
	fmt.Printf("\t[%s] [%s] ~> %s\r\n", Magenta(time.Now().Format("15:04:05")), Yellow("!!"), BrightYellow(msg))
}
func LogError(msg string) {
	fmt.Printf("\t[%s] [%s] ~> %s\r\n", Magenta(time.Now().Format("15:04:05")), Red("EE"), BrightRed(msg))
}

const (
	HIT = iota
	FAKE
	INVALID
)

func LogCode(sender string, guild string, start time.Time, code string, _type int) {
	if len(guild) == 0 {
		guild = "DM"
	}
	var codeType string
	switch _type {
	case HIT:
		codeType = color.Sprintf("<green>Redeemed</>")
		code = color.Sprintf("<green>%s</>", code)
	case FAKE:
		codeType = color.Sprintf("<red>Invalid</>")
		code = color.Sprintf("<red>%s</>", code)
	case INVALID:
		codeType = color.Sprintf("<red>Invalid Or Already Redeemed</>")
		code = color.Sprintf("<red>%s</>", code)
	}
	color.Printf("<white>[</><magenta>%s</><white>]</> <comment>Dropped By:</> <blue>%s</> <gray>|</> <comment>Drop Server:</> <lightMagenta>%s</> <gray>|</> <comment>Drop Latency:</> %v <gray>|</> Discord.gift/%s [%s]\r\n", start.Format("15:04:05"), sender, guild, time.Since(start), code, codeType)
}

func LogGiveaway(guild string, entered bool) {
	if entered {
		color.Printf("<white>[</><magenta>%s</><white>]</> <comment>Joined giveaway in:</> <blue>%s</>", time.Now().Format("15:04:05"), guild)
	} else {
		color.Printf("<white>[</><magenta>%s</><white>]</> <comment>Won giveaway in:</> <green>%s</>", time.Now().Format("15:04:05"), guild)
	}
}

func CallClear() {
	value, ok := clear[runtime.GOOS] //runtime.GOOS -> linux, windows, darwin etc.
	if ok {                          //if we defined a clear func for that platform:
		value() //we execute it
	} else { //unsupported platform
		panic("Your platform is unsupported! I can't clear terminal screen :(")
	}
}

func StrInArr(haystack []string, needle string) bool {
	for _, k := range haystack {
		if k == needle {
			return true
		}
	}
	return false
}

func FmtDuration(d time.Duration) string {
	d = d.Round(time.Second)
	h := d / time.Hour
	d -= h * time.Hour
	m := d / time.Minute
	d -= m * time.Minute
	s := d / time.Second
	return fmt.Sprintf("%02d:%02d:%02d", h, m, s)
}

const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

func StringWithCharset(length int, charset string) string {
	b := make([]byte, length)
	for i := range b {
		r := int(rand.Int63n(int64(len(charset))))
		if r < 0 || r > len(charset) {
			r = 0
		}
		b[i] = charset[r]
	}
	return string(b)
}

func StringOfLength(length int) string {
	return StringWithCharset(length, charset)
}

func HexStr(str string) string {
	return hex.EncodeToString([]byte(str))
}

func GetStringInBetween(str string, start string, end string) (result string) {
	s := strings.Index(str, start)
	if s == -1 {
		return
	}
	s += len(start)
	e := strings.Index(str[s:], end)
	if e == -1 {
		return
	}
	return str[s : s+e]
}

func ExtractData(str string, sel string) []string {
	re := regexp.MustCompile(fmt.Sprintf("%s(.*?)%s/m", sel, sel))
	return re.FindAllString(str, -1)
}

func Extract(str string, sel string) string {
	re := regexp.MustCompile(fmt.Sprintf("%s(.*?)%s", sel, sel))
	matches := re.FindStringSubmatch(str)
	return matches[0]
}

func GetInputStr() string {
	reader := bufio.NewReader(os.Stdin)
	opt, _ := reader.ReadString('\n')
	return strings.ReplaceAll(strings.ReplaceAll(opt, "\r", ""), "\n", "")
}

func HasAny(thing string, shit []string) bool {
	for _, v := range shit {
		if strings.Contains(thing, v) {
			return true
		}
	}
	return false
}

func ArrContains(arr []string, needle string) bool {
	for _, k := range arr {
		if k == needle {
			return true
		}
	}
	return false
}

func AskYesNo(msg string) bool {
	fmt.Println("\t" + msg)
	a := GetInputStr()
	if HasAny(a, []string{"y", "Y", "Yes", "yes"}) {
		return true
	}
	return false
}

func FileExists(filename string) bool {
	info, err := os.Stat(filename)
	if os.IsNotExist(err) {
		return false
	}
	return !info.IsDir()
}

func DirExists(filename string) bool {
	info, err := os.Stat(filename)
	if os.IsNotExist(err) {
		return false
	}
	return info.IsDir()
}

func FileLines(path string) int {

	length := 0

	file, err := os.Open(path)

	if err != nil {
		file, _ = os.Create(path)
	}

	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		if strings.TrimSpace(scanner.Text()) != "" {
			length++
		}
	}

	return length
}

func SliceToFile(slice []string, path string) {

	file, _ := os.Create(path)

	for _, str := range slice {
		file.WriteString(str + "\n")
	}

}

func FileToSlice(path string, sanitize bool) []string {

	file, err := os.Open(path)

	if err != nil {
		file, _ = os.Create(path)
	}

	scanner := bufio.NewScanner(file)

	var slice []string

	if sanitize == true {

		//Remove blank spaces
		var duplicates []string
		for scanner.Scan() {
			if strings.TrimSpace(scanner.Text()) != "" {
				duplicates = append(duplicates, strings.TrimSpace(scanner.Text()))
			}
		}

		//Remove Duplicates
		var lastStr string
		for _, duplicate := range duplicates {
			if lastStr != duplicate {
				lastStr = duplicate
				slice = append(slice, duplicate)
			}
		}

		file.Close()
		return slice
	}
	file.Close()
	return slice
}

func LoadInfo() []int {

	paths := []string{"params/keywords.txt", "params/pformats.txt", "params/ptypes.txt", "params/searchfuncs.txt", "params/domains.txt", "patterns.txt"}

	var values []int

	for _, path := range paths {

		switch path {
		case "params/keywords.txt":
			values = append(values, len(FileToSlice(path, true)))
		case "params/pformats.txt":
			values = append(values, len(FileToSlice(path, true)))
		case "params/ptypes.txt":
			values = append(values, len(FileToSlice(path, true)))
		case "params/searchfuncs.txt":
			values = append(values, len(FileToSlice(path, true)))
		case "params/domains.txt":
			values = append(values, len(FileToSlice(path, true)))
		case "patterns.txt":
			values = append(values, len(FileToSlice(path, true)))
		default:
			LogError("DID NOT LOAD ANYTHING")
		}
	}

	return values
}

func CompareTwoStrings(stringOne, stringTwo string) float32 {
	removeSpaces(&stringOne, &stringTwo)

	if value := returnEarlyIfPossible(stringOne, stringTwo); value >= 0 {
		return value
	}

	firstBigrams := make(map[string]int)
	for i := 0; i < len(stringOne)-1; i++ {
		a := fmt.Sprintf("%c", stringOne[i])
		b := fmt.Sprintf("%c", stringOne[i+1])

		bigram := a + b

		var count int

		if value, ok := firstBigrams[bigram]; ok {
			count = value + 1
		} else {
			count = 1
		}

		firstBigrams[bigram] = count
	}

	var intersectionSize float32
	intersectionSize = 0

	for i := 0; i < len(stringTwo)-1; i++ {
		a := fmt.Sprintf("%c", stringTwo[i])
		b := fmt.Sprintf("%c", stringTwo[i+1])

		bigram := a + b

		var count int

		if value, ok := firstBigrams[bigram]; ok {
			count = value
		} else {
			count = 0
		}

		if count > 0 {
			firstBigrams[bigram] = count - 1
			intersectionSize = intersectionSize + 1
		}
	}

	return (2.0 * intersectionSize) / (float32(len(stringOne)) + float32(len(stringTwo)) - 2)
}

func removeSpaces(stringOne, stringTwo *string) {
	*stringOne = strings.Replace(*stringOne, " ", "", -1)
	*stringTwo = strings.Replace(*stringTwo, " ", "", -1)
}

func returnEarlyIfPossible(stringOne, stringTwo string) float32 {
	// if both are empty strings
	if len(stringOne) == 0 && len(stringTwo) == 0 {
		return 1
	}

	// if only one is empty string
	if len(stringOne) == 0 || len(stringTwo) == 0 {
		return 0
	}

	// identical
	if stringOne == stringTwo {
		return 1
	}

	// both are 1-letter strings
	if len(stringOne) == 1 && len(stringTwo) == 1 {
		return 0
	}

	// if either is a 1-letter string
	if len(stringOne) < 2 || len(stringTwo) < 2 {
		return 0
	}

	return -1
}

func SplitSlice(slice []string, n int) [][]string {
	var divided [][]string
	if n == 1 {
		return append(divided, slice)
	}

	chunkSize := (len(slice) + n - 1) / n

	for i := 0; i < len(slice); i += chunkSize {
		end := i + chunkSize
		if end > len(slice) {
			end = len(slice)
		}
		divided = append(divided, slice[i:end])
	}
	return divided
}

func StatusStr(status int) string {
	switch status {
	case 0:
		return "Running"
	case 1:
		return "Stopping"
	}
	return "Unknown"
}

func DoCleanUrls(input []string) []string {
	var hosts []string
	var out []string
	for _, str := range input {
		//if m, err := regexp.MatchString(`(.*?)\?.+=`, str); err != nil && m {
		if !(strings.Contains(str, "http") && strings.Contains(str, "=") && strings.Contains(str, "?")) {
			continue
		}
		u, err := url.Parse(str)
		if err != nil {
			continue
		}
		if !StrInArr(hosts, u.Host) {
			hosts = append(hosts, u.Host)
			out = append(out, strings.ReplaceAll(str, "&amp;", "&"))
		}
		//}
	}
	return out
}

func GetFileHash(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}

	defer file.Close()
	hash := md5.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", err
	}
	hashInBytes := hash.Sum(nil)[:16]
	return hex.EncodeToString(hashInBytes), nil
}

func IsClosed(ch <-chan interface{}) bool {
	select {
	case <-ch:
		return true
	default:
	}

	return false
}
