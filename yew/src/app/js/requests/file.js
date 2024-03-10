export function uploadFileStream(file, file_path) {
    return new Promise((resolve, reject) => {
        const url = `http://localhost:8000/file${file_path.charAt(0) === '/' ? file_path : `/${file_path}`}`;

        let headers = new Headers();
        headers.append('Content-Type', file.type);

        fetch(url, {
            method: 'PUT',
            header: headers,
            body: file, // Stream the file directly as the request body
            credentials: 'include'
        })
            .then(response => {
                // Handle the response
                if (!response.ok) {
                    throw new Error('Upload failed');
                }
                return response.text();
            })
            .then(result => {
                resolve(result);
            })
            .catch(error => {
                reject(error);
            });
    });
}