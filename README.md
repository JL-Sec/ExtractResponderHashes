# Extract Responder Hashes

Simple Python utility for extracting and filtering NTLM/NetNTLM hashes from `Responder-Session.log` files.

## Features

- Extract NTLMv1 / NTLMv2 / NTLMv2-SSP hashes
- Filter by:
  - protocol
  - hash type
  - username
  - domain
  - date range
- Export usernames
- Show full matching log lines
- Output results to file

---

## Usage

```bash
python3 extract_responder_hashes.py -i Responder-Session.log
```

---

## Examples

### Extract only SMB NetNTLMv2 hashes

```bash
python3 extract_responder_hashes.py \
-i Responder-Session.log \
-P "SMB|SMBv2" \
-H "NTLMv2|NTLMv2-SSP"
```

### Export results to a file

```bash
python3 extract_responder_hashes.py \
-i Responder-Session.log \
-o hashes.txt
```

### Filter by username

```bash
python3 extract_responder_hashes.py \
-i Responder-Session.log \
-U administrator
```

### Extract usernames only

```bash
python3 extract_responder_hashes.py \
-i Responder-Session.log \
-u
```

### Show matching log lines with IP information

```bash
python3 extract_responder_hashes.py \
-i Responder-Session.log \
-I
```

---

## Requirements

- Python 3.x
- No external dependencies

---

## Disclaimer

This tool is intended for authorised security testing, lab environments, and internal assessments only.
