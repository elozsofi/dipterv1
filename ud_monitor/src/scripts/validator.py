def read_file_to_set(file_path):
    with open(file_path, 'r') as file:
        return set(line.strip() for line in file.readlines()) # reading entries as sets

# compare files line by line
def compare_files(file1, file2):
    set1 = read_file_to_set(file1)
    set2 = read_file_to_set(file2)
    
    # find diffs
    diff1 = set1 - set2 
    diff2 = set2 - set1

    if diff1:
        print("Entries in", file1, "but not in", file2)
        for entry in diff1:
            print(entry)
    else:
        print(f"No unique entries in {file1}.")

    if diff2:
        print("\\nEntries in", file2, "but not in", file1)
        for entry in diff2:
            print(entry)
    else:
        print(f"No entries unique to {file2}.")

    if not diff1 and not diff2:
        print("Both files have identical entries.")

# Replace 'file1.txt' and 'file2.txt' with the actual file paths
file1 = "file1.txt"
file2 = "file2.txt"
compare_files(file1, file2)