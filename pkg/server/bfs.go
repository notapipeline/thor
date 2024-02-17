// This file is part of thor (https://github.com/notapipeline/thor).
//
// Copyright (c) 2024 Martin Proffitt <mproffitt@choclab.net>.
//
// This program is free software: you can redistribute it and/or modify it under
// the terms of the GNU General Public License as published by the Free Software
// Foundation, either version 3 of the License, or (at your option) any later
// version.
//
// This program is distributed in the hope that it will be useful, but WITHOUT ANY
// WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A
// PARTICULAR PURPOSE. See the GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License along with
// this program. If not, see <https://www.gnu.org/licenses/>.

package server

import (
	"fmt"
	"net/http"
	"strings"

	assetfs "github.com/elazarl/go-bindata-assetfs"
	"github.com/gin-gonic/gin"
)

// BinFileSystem : Binary file system for serving compiled assets
type BinFileSystem struct {
	FileSystem http.FileSystem
	Root       string
}

// Open : Open a given file from compiled binary file system
func (binFS *BinFileSystem) Open(name string) (http.File, error) {
	return binFS.FileSystem.Open(name)
}

// Exists : Check if a given file exists in the filesystem
func (binFS *BinFileSystem) Exists(prefix string, filepath string) bool {
	var url string = strings.TrimPrefix(filepath, prefix)
	if len(url) < len(filepath) {
		if _, err := binFS.FileSystem.Open(url); err == nil {
			return true
		}
	}
	return false
}

// GetBinFileSystem : Get the binary filesystem object
func GetBinFileSystem(root string) *BinFileSystem {
	fs := &assetfs.AssetFS{
		Asset:     Asset,
		AssetDir:  AssetDir,
		AssetInfo: AssetInfo,
		Prefix:    root,
		Fallback:  "",
	}

	return &BinFileSystem{fs, root}
}

// Collection : Load a collection of files from the filsystem and send them
// back over the assigned gin.Context
func (binFS *BinFileSystem) Collection(c *gin.Context) {
	result := Result{}
	result.Code = 200
	result.Result = "OK"
	var err error
	var collection = c.Params.ByName("collection")
	result.Message = make([]string, 0)
	result.Message, err = AssetDir(fmt.Sprintf("%s/img/%s", binFS.Root, collection))
	if err != nil {
		result.Code = 404
		result.Result = "Error"
		result.Message = err
	}
	c.JSON(result.Code, result)
}
