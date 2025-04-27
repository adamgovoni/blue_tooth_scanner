import csv

input_file = 'oui.csv'
output_file = 'mac_vendors.csv'

with open(input_file, mode='r') as infile, open(output_file, mode='w', newline='') as outfile:
    reader = csv.DictReader(infile)
    writer = csv.writer(outfile)
    
    for row in reader:
        assignment = row['Assignment'].strip()
        org_name = row['Organization Name'].strip()

        # Only process entries that look like a MAC prefix (should be 6 hex digits)
        if len(assignment) == 6:
            mac_prefix = ":".join([assignment[i:i+2] for i in range(0, 6, 2)])
            writer.writerow([mac_prefix, org_name])

print(f"Converted {input_file} to {output_file}")
