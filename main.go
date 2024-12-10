package main

import (
	"io"
	"log"
	"net/http"
	"os"

	_ "github.com/joho/godotenv/autoload"
	"github.com/schollz/progressbar/v3"
)

func main() {
	log.Println("[INFO] Downloading the advisory database zip file...")
	err := downloadGHSAZip()
	if err != nil {
		log.Fatalln("\n[ERROR] Could not download the advisory database: " + err.Error())
	}
	log.Println("\n[INFO] Download of the advisory database zip file is successful!")
}

func downloadGHSAZip() error {
	req, err := http.NewRequest("GET", os.Getenv("ADVISORY_DATABASE_URL"), nil)
	if err != nil {
		return err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	f, _ := os.OpenFile("advisory-database.zip", os.O_CREATE|os.O_WRONLY, 0644)
	defer f.Close()

	bar := progressbar.DefaultBytes(
		resp.ContentLength,
		"downloading",
	)
	_, err = io.Copy(io.MultiWriter(f, bar), resp.Body)
	if err != nil {
		return err
	}

	return nil
}
