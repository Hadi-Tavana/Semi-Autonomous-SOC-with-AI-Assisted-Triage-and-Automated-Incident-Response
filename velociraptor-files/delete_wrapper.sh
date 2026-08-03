#!/bin/bash
# delete_wrapper.sh
FILE_PATH="${1//\\/\\\\}"  # Replace \ with \\
python3 delete_script_edited.py "$FILE_PATH"
