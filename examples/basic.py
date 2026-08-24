from secureinjections import Scanner

scanner = Scanner()
result = scanner.scan("Please summarize this message")

print(result.to_dict())
