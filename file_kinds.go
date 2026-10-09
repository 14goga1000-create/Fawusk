package main

import (
	"path"
	"strings"
)

func iconKind(a archiveEntry) string {
	if a.Directory {
		return "folder"
	}
	switch strings.ToLower(path.Ext(a.Name)) {
	case ".faw", ".zip", ".rar", ".7z", ".tar", ".gz", ".bz2", ".xz", ".tgz", ".iso":
		return "archive"
	case ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".webp", ".tif", ".tiff", ".ico", ".avif", ".heic", ".svg":
		return "image"
	case ".mp4", ".mkv", ".webm", ".avi", ".mov", ".m4v", ".wmv", ".mpg", ".mpeg", ".flv", ".3gp", ".ts", ".m2ts", ".ogv":
		return "video"
	case ".mp3", ".wav", ".flac", ".ogg", ".m4a", ".aac", ".wma", ".opus", ".aiff", ".mid":
		return "audio"
	case ".pdf":
		return "pdf"
	case ".doc", ".docx", ".odt", ".rtf", ".docm":
		return "document"
	case ".xls", ".xlsx", ".ods", ".csv", ".tsv", ".xlsm":
		return "spreadsheet"
	case ".ppt", ".pptx", ".odp", ".pptm":
		return "presentation"
	case ".exe", ".com", ".dll", ".msi", ".scr", ".sys", ".cpl", ".ocx":
		return "application"
	case ".bat", ".cmd", ".ps1", ".vbs", ".js", ".py", ".sh", ".go", ".c", ".cpp", ".h", ".rs", ".java", ".json", ".xml", ".html", ".css", ".yaml", ".yml", ".toml":
		return "code"
	case ".txt", ".md", ".log", ".ini", ".cfg":
		return "text"
	case ".ttf", ".otf", ".woff", ".woff2":
		return "font"
	case ".bin", ".dat", ".db", ".sqlite":
		return "data"
	}
	return "file"
}
