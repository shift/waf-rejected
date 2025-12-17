#!/bin/bash

set -e

# Create old_docs directory if it doesn't exist
mkdir -p old_docs

# Find all .md files, excluding those already in old_docs
find . -name "*.md" -type f -not -path "./old_docs/*" | while read -r file; do
    # Remove leading ./
    file=${file#./}
    # Replace / with _ in the filename
    new_name=$(echo "$file" | tr '/' '_')
    # Git move the file
    git mv "$file" "old_docs/$new_name"
done

echo "All .md files have been moved to old_docs/ with renamed filenames."