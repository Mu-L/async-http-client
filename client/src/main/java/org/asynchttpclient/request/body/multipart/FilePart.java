/*
 *    Copyright (c) 2014-2024 AsyncHttpClient Project. All rights reserved.
 *
 *    Licensed under the Apache License, Version 2.0 (the "License");
 *    you may not use this file except in compliance with the License.
 *    You may obtain a copy of the License at
 *
 *        http://www.apache.org/licenses/LICENSE-2.0
 *
 *    Unless required by applicable law or agreed to in writing, software
 *    distributed under the License is distributed on an "AS IS" BASIS,
 *    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *    See the License for the specific language governing permissions and
 *    limitations under the License.
 */
package org.asynchttpclient.request.body.multipart;

import java.io.File;
import java.nio.charset.Charset;

public class FilePart extends FileLikePart {

    private final File file;

    public FilePart(String name, File file) {
        this(name, file, null);
    }

    public FilePart(String name, File file, String contentType) {
        this(name, file, contentType, null);
    }

    public FilePart(String name, File file, String contentType, Charset charset) {
        this(name, file, contentType, charset, null);
    }

    public FilePart(String name, File file, String contentType, Charset charset, String fileName) {
        this(name, file, contentType, charset, fileName, null);
    }

    public FilePart(String name, File file, String contentType, Charset charset, String fileName, String contentId) {
        this(name, file, contentType, charset, fileName, contentId, null);
    }

    public FilePart(String name, File file, String contentType, Charset charset, String fileName, String contentId, String transferEncoding) {
        super(name, contentType, charset, fileName != null ? fileName : file.getName(), contentId, transferEncoding);
        if (!file.isFile()) {
            throw new IllegalArgumentException("File is not a normal file " + file.getAbsolutePath());
        }
        if (!file.canRead()) {
            throw new IllegalArgumentException("File is not readable " + file.getAbsolutePath());
        }
        this.file = file;
    }

    public File getFile() {
        return file;
    }
}
