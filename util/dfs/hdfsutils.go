// Copyright (C) 2018 go-gt authors
//
// This file is part of the go-gt library.
//
// the go-gt library is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// the go-gt library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with the go-gt library.  If not, see <http://www.gnu.org/licenses/>.
//

package dfs

import (
	"bytes"
	corepb "gt.pro/gtio/go-gt/core/pb"
	"gt.pro/gtio/go-gt/util/logging"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"io/ioutil"
	"net/http"
	"path"
)

var (
	HDFSURLPrefix = "http://192.168.21.41:50070/webhdfs/v1/"

	CreateDirectory = "?op=MKDIRS&user.name=root"
	CreateFile      = "?op=CREATE&user.name=root"
	GetStatus       = "?op=GETFILESTATUS"
	Open            = "?op=OPEN"
)

var (
	FileNameIsEmptyErr = errors.New("file name is empty")
	CreateFileErr      = errors.New("crete file response code is not 201")
	NotFoundErr        = errors.New("not found")
)

func createBucket(bucketName string, dfsPrefix string) error {
	url := dfsPrefix + bucketName + CreateDirectory
	req, err := http.NewRequest(http.MethodPut, url, nil)
	if err != nil {
		logging.VLog().WithFields(logrus.Fields{
			"bucket": bucketName,
			"url":    url,
		}).Error(err.Error())
		return err
	}
	req.Header.Set("Content-Type", "application/octet-stream")
	rep, err := http.DefaultClient.Do(req)
	if err != nil {
		logging.VLog().WithFields(logrus.Fields{
			"bucket": bucketName,
			"url":    url,
		}).Error(err.Error())
		return err
	}

	if rep.StatusCode != http.StatusOK {
		logging.VLog().WithFields(logrus.Fields{
			"bucket": bucketName,
			"url":    url,
		}).Error(err)
		return err
	}

	logging.VLog().WithFields(logrus.Fields{
		"bucket": bucketName,
		"url":    url,
	}).Debug("[createBucket] create bucket success")
	return nil
}

func createFromData(bucket string, file *corepb.File, dfsPrefix string) error {
	err := fileOrDirectoryIsExist(bucket, dfsPrefix)
	if err != nil && err == NotFoundErr {
		err = createBucket(bucket, dfsPrefix)
	}
	if err != nil {
		return err
	}

	fileName := file.GetName()
	url := dfsPrefix + path.Join(bucket, fileName) + CreateFile
	req, err := http.NewRequest(http.MethodPut, url, bytes.NewReader(file.GetContent()))
	if err != nil {
		logging.VLog().WithFields(logrus.Fields{
			"bucket":   bucket,
			"fileName": fileName,
			"url":      url,
		}).Error(err.Error())
		return err
	}
	req.Header.Set("Content-Type", "application/octet-stream")

	rep, err := http.DefaultClient.Do(req)
	if err != nil {
		logging.VLog().WithFields(logrus.Fields{
			"bucket":   bucket,
			"fileName": fileName,
			"url":      url,
		}).Error(err.Error())
		return err
	}

	body, err := ioutil.ReadAll(rep.Body)
	if rep.StatusCode != http.StatusCreated {
		logging.VLog().WithFields(logrus.Fields{
			"bucket":       bucket,
			"fileName":     fileName,
			"url":          url,
			"responseCode": rep.StatusCode,
			"responseBody": string(body),
		}).Error("create file failed")
		return CreateFileErr
	}

	if err != nil {
		logging.VLog().WithFields(logrus.Fields{
			"bucket":       bucket,
			"fileName":     fileName,
			"url":          url,
			"responseCode": rep.StatusCode,
		}).Error("read response body error")
		return err
	}

	logging.VLog().WithFields(logrus.Fields{
		"bucket":       bucket,
		"fileName":     fileName,
		"url":          url,
		"body":         string(body),
		"responseCode": rep.StatusCode,
	}).Debug("[createFromData] create file success")
	return nil
}

func fileOrDirectoryIsExist(fileName string, dfsPrefix string) error {
	if len(fileName) == 0 {
		return FileNameIsEmptyErr
	}
	url := dfsPrefix + fileName + GetStatus
	resp, err := http.Get(url)
	if err != nil {
		logging.VLog().WithFields(logrus.Fields{
			"fileName": fileName,
			"url":      url,
		}).Debug(err)
		return err
	}
	if resp.StatusCode == http.StatusNotFound {
		return NotFoundErr
	}
	return nil
}

func GetResult(bucket string, file *corepb.File, dfsPrefix []string) []byte {
	if dfsPrefix == nil || len(dfsPrefix) == 0 {
		logging.VLog().Debug("dfs prefix is nil or empty")
		return nil
	}
	url := bucket + "/" + file.Name + Open
	go uploadFileToDfs(bucket, file, dfsPrefix)
	return []byte(url)
}

func uploadFileToDfs(bucket string, file *corepb.File, dfsPrefix []string) {
	for _, prefix := range dfsPrefix {
		if len(prefix) == 0 {
			continue
		}
		err := createFromData(bucket, file, prefix)
		if err == nil {
			return
		}
	}
}
