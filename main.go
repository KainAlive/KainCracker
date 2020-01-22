// TODO: Implement permutation AND threading

package main

import (
	"github.com/fatih/color"
	"github.com/integrii/flaggy"
	"fmt"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"bufio"
	"os"
	"encoding/hex"
	"strings"
	"time"
)

var password_file_path = ""
var hash_file_path = "" 
var hash_mode = ""
var permut bool = false
var charset = ""
var min_length int = 0
var max_length int = 0

var password_list = []string{}
var hashes = []string{}

func main() {

	flaggy.String(&password_file_path, "P", "passwordlist", "Path to passwordlist")
	flaggy.String(&hash_file_path, "H", "hashlist", "Path to hashlist")
	flaggy.String(&hash_mode, "m", "mode", "Hashmode (md5, sha1, sha256, sha512)")
	flaggy.Bool(&permut, "p", "permut", "Use permutation (true / [false]")
	flaggy.String(&charset, "c", "charset", "Charset to use for permutation")
	flaggy.Int(&min_length, "", "min", "Minimum of permutatoin password")
	flaggy.Int(&max_length, "", "max", "Maximum of permutation password")

	flaggy.Parse()

	if password_file_path == "" || hash_file_path == "" || hash_mode == "" {
		fmt.Errorf("Error")
	}
	
	hashfile, err := os.Open(hash_file_path)
	if err != nil {
		color.Red("[!] ERROR: ", err)
		os.Exit(0)
	}
	scanner := bufio.NewScanner(hashfile)
	for scanner.Scan() {
		hashes = append(hashes, scanner.Text())
	}
	color.Green("[+] Reading password list")
	password_file, err := os.Open(password_file_path)
	if err != nil {
		color.Red("[!] ERROR: ", err)
		os.Exit(0)
	}
	scanner = bufio.NewScanner(password_file)
	for scanner.Scan() {
		password_list = append(password_list, string(strings.Split(strings.TrimSuffix(scanner.Text(), "\n"), " ")[0])) 
	}

	if hash_mode == "md5" {
		crackMD5()
	}
	if hash_mode == "sha1" {
		crackSHA1()
	}
	if hash_mode == "sha256" {
		crackSHA256()
	}
	if hash_mode == "sha512" {
		crackSHA512()
	}
	
}

func crackMD5() {
	fmt.Println("[*] Starting MD5 cracker...")
	start_time := time.Now()
	md5_hasher := md5.New()
	for _, hash := range hashes {
		for _, password := range password_list {
			md5_hasher.Write([]byte(password))
			md5_hash := hex.EncodeToString(md5_hasher.Sum(nil))
			if md5_hash == string(hash) {
				fmt.Println("[+] Found password:", hash, ":", password)
				break
			} else {
				md5_hasher.Reset()
				continue
			}
		}
	}
	t := time.Now()
	fmt.Println("[+] Took:", t.Sub(start_time))
}

func crackSHA1() {
	fmt.Println("[*] Starting SHA1 cracker...")
	start_time := time.Now()
	sha1_hasher := sha1.New()
	for _, hash := range hashes {
		for _, password := range password_list {
			sha1_hasher.Write([]byte(password))
			sha1_hash := hex.EncodeToString(sha1_hasher.Sum(nil))
			if sha1_hash == string(hash) {
				fmt.Println("[+] Found password:", hash, ":", password)
				break
			} else {
				sha1_hasher.Reset()
				continue
			}
		}
	}
	t := time.Now()
	fmt.Println("[+] Took:", t.Sub(start_time))
}

func crackSHA256() {
	fmt.Println("[*] Starting SHA256 cracker...")
	start_time := time.Now()
	sha256_hasher := sha256.New()
	for _, hash := range hashes {
		for _, password := range password_list {
			sha256_hasher.Write([]byte(password))
			sha256_hash := hex.EncodeToString(sha256_hasher.Sum(nil))
			if sha256_hash == string(hash) {
				fmt.Println("[+] Found password:", hash, ":", password)
				break
			} else {
				sha256_hasher.Reset()
				continue
			}
		}
	}
	t := time.Now()
	fmt.Println("[+] Took:", t.Sub(start_time))
}

func crackSHA512() {
	fmt.Println("[*] Starting sha512 cracker...")
	start_time := time.Now()
	sha512_hasher := sha512.New()
	for _, hash := range hashes {
		for _, password := range password_list {
			sha512_hasher.Write([]byte(password))
			sha512_hash := hex.EncodeToString(sha512_hasher.Sum(nil))
			if sha512_hash == string(hash) {
				fmt.Println("[+] Found password:", hash, ":", password)
				break
			} else {
				sha512_hasher.Reset()
				continue
			}
		}
	}
	t := time.Now()
	fmt.Println("[+] Took:", t.Sub(start_time))
}