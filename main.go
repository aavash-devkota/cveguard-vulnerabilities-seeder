package main

import (
	"archive/zip"
	"cveguard-vulnerabilities-seeder/schema"
	"database/sql"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	_ "github.com/go-sql-driver/mysql"
	_ "github.com/joho/godotenv/autoload"
	"github.com/schollz/progressbar/v3"
)

var DOWNLOAD_ZIP_NAME string = "advisory-database.zip"

func main() {
	toDownloadZip := os.Getenv("TO_DOWNLOAD_ZIP")

	if strings.ToLower(toDownloadZip) != "false" {
		log.Println("[INFO] Downloading the advisory database zip file...")
		err := downloadGHSAZip()
		if err != nil {
			log.Fatalln("\n[ERROR] Could not download the advisory database: " + err.Error())
		}
		log.Println("\n[INFO] Download of the advisory database zip file is successful!")
	} else {
		log.Println("[WARN] The step to download the advisory database zip file is skipped due to the environment variable.")
	}

	log.Println("[INFO] Seeding the database...")
	seedToDatabase()
	log.Println("[INFO] Database seed is successful!")
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

	f, _ := os.OpenFile(DOWNLOAD_ZIP_NAME, os.O_CREATE|os.O_WRONLY, 0644)
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

func seedToDatabase() {
	db, err := sql.Open("mysql", os.Getenv("DB_DATA_SOURCE_NAME"))
	if err != nil {
		log.Fatalln("Could not connect to the database: " + err.Error())
	}
	db.SetConnMaxLifetime(time.Minute * 3)
	db.SetMaxOpenConns(10)
	db.SetMaxIdleConns(10)

	// Open the zip file
	read, err := zip.OpenReader(DOWNLOAD_ZIP_NAME)
	if err != nil {
		log.Fatalf("Could not open the zip file: %s", err)
	}
	defer read.Close()

	// Get the contents of the zip file
	for _, f := range read.File {
		// Ignore folders
		if f.FileInfo().IsDir() {
			continue
		}
		// Ignore if not a GHSA JSON file
		if !strings.HasPrefix(f.FileInfo().Name(), "GHSA") {
			continue
		}

		// Get the file name
		// fmt.Printf("File Name: %s\n", f.Name)

		func() {
			// Open the file
			v, err := f.Open()
			if err != nil {
				log.Fatalf("Could not open a file in the zip (%s): %s", f.Name, err)
			}
			defer v.Close()

			body, err := io.ReadAll(v)
			if err != nil {
				log.Fatalf("Could not read a file in the zip (%s): %s", f.Name, err)
			}

			var record schema.Entry
			err = json.Unmarshal(body, &record)
			if err != nil {
				log.Fatalf("Could not parse the CVE JSON (%s): %s", f.Name, err)
			}

			// Get proper data for database

			introducedVersion := ""
			fixedVersion := ""

			if len(record.Affected) == 0 {
				return
			}

			if len(record.Affected[0].Ranges) == 0 {
				return
			}

			// Only run for npm packages
			if record.Affected[0].Package.Ecosystem != "npm" {
				return
			}

			for _, el := range record.Affected[0].Ranges[0].Events {
				if el.Introduced != "" {
					introducedVersion = el.Introduced
				}
				if el.Fixed != "" {
					fixedVersion = el.Fixed
				}
			}

			var cveId *string = nil
			if len(record.Aliases) != 0 {
				cveId = &record.Aliases[0]
			}

			_, err = db.Exec(`
				INSERT INTO vulnerabilities
				(cve_id, ghsa_id, ecosystem, name, introduced_version, fixed_version, details, published_at, modified_at) VALUES
				(?, ?, ?, ?, ?, ?, ?, ?, ?)
				ON DUPLICATE KEY UPDATE
				fixed_version = ?, modified_at = ?
			`,
				cveId,
				record.ID,
				record.Affected[0].Package.Ecosystem,
				record.Affected[0].Package.Name,
				introducedVersion,
				fixedVersion,
				record.Details,
				record.Published,
				record.Modified,
				// ON DUPLICATE
				fixedVersion,
				record.Modified,
			)
			if err != nil {
				log.Fatalln(err)
			}
			log.Println("[INFO] Added " + record.ID)
		}()
	}
}
