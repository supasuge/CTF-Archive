# USCG log + database

- [Converting the USCG signal timestamp to a datetime object](#converting\the\uscg\signal\timestamp\to\a\datetime\object)
- [Defining the latitude and longitude from the USCG log](#defining\the\latitude\and\longitude\from\the\uscg\log)
- [Defining the tolerance for the coordinates and time](#defining\the\tolerance\for\the\coordinates\and\time)
- [SQL query to find matching records](#sql\query\to\find\matching\records)
- [Executing the query](#executing\the\query)
- [Converting the results to a DataFrame for easier processing](#converting\the\results\to\a\dataframe\for\easier\processing)
- [Function to combine date and time columns into a single datetime column](#function\to\combine\date\and\time\columns\into\a\single\datetime\column)
    - [Step 3: Querying the Database](#Step\3:\Querying\the\Database)
          - [Constraints as to the need coordinates/timestamps etc.](#Constraints\as\to\the\need\coordinates/timestamps\etc.)
  - [Results](#Results)
- [Unraveling the Mystery: Analyzing USCG Signal Data with the NSA Database](#unraveling\the\mystery:\analyzing\uscg\signal\data\with\the\nsa\database)
  - [Introduction](#Introduction)
  - [Methodology](#Methodology)
    - [Step 1: Analyzing USCG Signal Data](#Step\1:\Analyzing\USCG\Signal\Data)
    - [Step 2: Accessing the NSA Database](#Step\2:\Accessing\the\NSA\Database)
    - [Step 3: Querying the Database](#Step\3:\Querying\the\Database)
  - [Results](#Results)
  - [Conclusion](#Conclusion)

 ```python
import sqlite3
nsa_db_file_path = 'database.db'
conn = sqlite3.connect(nsa_db_file_path)
cursor = conn.cursor()


cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")

tables = cursor.fetchall()

print(tables)



```
**The NSA database contains the following tables:**
1. `audio_object`
2. `sqlite_sequence`
3. `location`
4. `timestamp`
5. `event`

*The schema of the relevant tables in the NSA database is as follows:*

1. `audio_object`:
    
    - id (INTEGER)
    - transcript
    - contentUrl (BLOB)
    - description
    - name (TEXT)
    - encodingFormat
2. `location`:
    
    - id (INTEGER)
    - latitude
    - longitude
    - elevation
3. `timestamp`:
    
    - id (INTEGER)
    - recTime (TEXT)
    - recDate (TEXT)
4. `event`:
    
    - id (INTEGER)
    - location_id (INTEGER)
    - name (TEXT)
    - audio_object_id (INTEGER)
    - timestamp_id (INTEGER)

```python
import pandas as pd
from datetime import datetime, timedelta

# Converting the USCG signal timestamp to a datetime object
uscg_timestamp = datetime.strptime("02/07/2023, 18:17:25", "%m/%d/%Y, %H:%M:%S")

# Defining the latitude and longitude from the USCG log
uscg_latitude = 28.34992
uscg_longitude = -84.69568

# Defining the tolerance for the coordinates and time
coordinate_tolerance = 0.01  # 1/100th of a degree
time_tolerance = timedelta(minutes=10)

# SQL query to find matching records
query = '''
SELECT e.id, l.latitude, l.longitude, t.recDate, t.recTime
FROM event e
JOIN location l ON e.location_id = l.id
JOIN timestamp t ON e.timestamp_id = t.id
WHERE ABS(l.latitude - ?) <= ? AND ABS(l.longitude - ?) <= ?
'''

# Executing the query
cursor.execute(query, (uscg_latitude, coordinate_tolerance, uscg_longitude, coordinate_tolerance))
matching_records = cursor.fetchall()

# Converting the results to a DataFrame for easier processing
df = pd.DataFrame(matching_records, columns=['event_id', 'latitude', 'longitude', 'recDate', 'recTime'])

# Function to combine date and time columns into a single datetime column
def combine_date_time(row):
    return datetime.strptime(f"{row['recDate']}, {row['recTime']}", "%m/%d/%Y, %H:%M:%S")

df['datetime'] = df.apply(combine_date_time, axis=1)
filtered_df = df[abs(df['datetime'] - uscg_timestamp) <= time_tolerance]
```

1. Accessing the database
	- The NSA datbase was structured into several tables, but the relevant ones for our analysis were `audio_object`, `location`, `timestamp`, `event`. Their schema was as follows:
		- `audio_object`: Contains details about the audio object, including an ID and transcript.
		- `location`: Holds geographic data like latitude and longitude.
		- `timestamp`: Stores time-related information.
		- `event`: Links audio objects with their corresponding locations and timestamps.

### Step 3: Querying the Database

The query aimed to find events in the NSA database that matched the USCG criteria:
###### Constraints as to the need coordinates/timestamps etc.
1. **Geographic Proximity**: Within 1/100th of a degree of the given coordinates.
2. **Temporal Proximity**: Within a 10-minute window of the given timestamp.

## Results

The query revealed two records that met both the geographic and temporal criteria:

- **Event ID 196**
- **Event ID 767**

These records were closely aligned in time and location with the USCG signal, suggesting a potential correlation.



Certainly! Here's a detailed writeup in Markdown format, suitable for a post on Medium, detailing the process and logical steps taken to analyze the data provided by the US Coast Guard and the NSA database:

---

# Unraveling the Mystery: Analyzing USCG Signal Data with the NSA Database

## Introduction
Recently, the US Coast Guard (USCG) detected an unregistered signal over 30 nautical miles from the continental US. To investigate the source, they turned to the NSA database for potential matches. As a Data Analyst, my task was to sift through the data and find any records that might hint at the signal's origin.

## Methodology
The process involved three key steps:
1. **Analyzing the USCG Signal Data**: The signal data provided by the USCG was contained in a file named `USCG.log`.
2. **Accessing the NSA Database**: The NSA database was stored in a file named `database.db`.
3. **Matching Criteria**: The objective was to find records in the NSA database that met the USCG's specific criteria:
    - Geographic coordinates within 1/100th of a degree of the signal's location.
    - Record timestamps no more than 10 minutes apart.

### Step 1: Analyzing USCG Signal Data

Upon examining the `USCG.log` file, I found it to contain JSON data with two crucial pieces of information:
- **Coordinates**: Latitude 28.34992, Longitude -84.69568.
- **Timestamp**: February 7, 2023, at 18:17:25.

### Step 2: Accessing the NSA Database

The NSA database was structured into several tables, but the relevant ones for our analysis were `audio_object`, `location`, `timestamp`, and `event`. Their schemas were as follows:

- `audio_object`: Contains details about the audio object, including an ID and transcript.
- `location`: Holds geographic data like latitude and longitude.
- `timestamp`: Stores time-related information.
- `event`: Links audio objects with their corresponding locations and timestamps.

### Step 3: Querying the Database

The query aimed to find events in the NSA database that matched the USCG criteria:
1. **Geographic Proximity**: Within 1/100th of a degree of the given coordinates.
2. **Temporal Proximity**: Within a 10-minute window of the given timestamp.

## Results

The query revealed two records that met both the geographic and temporal criteria:
- **Event ID 196**
- **Event ID 767**

These records were closely aligned in time and location with the USCG signal, suggesting a potential correlation.

## Conclusion

The analysis of the USCG signal data and the subsequent querying of the NSA database yielded two promising leads. By closely adhering to the specified criteria, we identified events that could potentially unveil the source of the mysterious signal. This collaboration between the USCG and NSA highlights the importance of data analysis in solving real-world challenges.

---

# No Token Left Behind

**Description**
```
Aaliyah is showing you how Intelligence Analysts work. She pulls up a piece of intelligence she thought was interesting. It shows that APTs are interested in acquiring hardware tokens used for accessing DIB networks. Those are generally controlled items, how could the APT get a hold of one of those?

DoD sometimes sends copies of procurement records for controlled items to the NSA for analysis. Aaliyah pulls up the records but realizes it’s in a file format she’s not familiar with. Can you help her look for anything suspicious?

If DIB companies are being actively targeted by an adversary the NSA needs to know about it so they can help mitigate the threat.

Help Aaliyah determine the outlying activity in the dataset given
```

In this challenge we are provided with the file `shipping.db`.


After downloading the file, I ran `file` on it:
```bash
file shipping.ods
shipping.ods: Zip data (MIME type "application/vnd.oasis.O"?)
```

A quick google search for this file type presents: 
![[Pasted image 20240919135956.png]]


I tried unzipping the data at first and examining the contents manually:
```bash
unzip shipping.ods -d shipping_content

ls -alR shipping_content/
.:
total 1600
drwxrwxr-x 5 kali kali    4096 Sep 19 13:00 .
drwxrwxr-x 4 kali kali    4096 Sep 19 13:52 ..
drwxrwxr-x 9 kali kali    4096 Sep 19 13:00 Configurations2
drwxrwxr-x 2 kali kali    4096 Sep 19 13:00 META-INF
drwxrwxr-x 2 kali kali    4096 Sep 19 13:00 Thumbnails
-rw-rw-r-- 1 kali kali 1585878 Sep 15 06:44 content.xml
-rw-rw-r-- 1 kali kali     899 Sep 15 06:44 manifest.rdf
-rw-rw-r-- 1 kali kali     628 Sep 15 06:44 meta.xml
-rw-rw-r-- 1 kali kali      46 Sep 15 06:44 mimetype
-rw-rw-r-- 1 kali kali    4532 Sep 15 06:44 settings.xml
-rw-rw-r-- 1 kali kali    8189 Sep 15 06:44 styles.xml

./Configurations2:
total 36
drwxrwxr-x 9 kali kali 4096 Sep 19 13:00 .
drwxrwxr-x 5 kali kali 4096 Sep 19 13:00 ..
drwxrwxr-x 2 kali kali 4096 Sep 15 06:44 floater
drwxrwxr-x 2 kali kali 4096 Sep 15 06:44 menubar
drwxrwxr-x 2 kali kali 4096 Sep 15 06:44 popupmenu
drwxrwxr-x 2 kali kali 4096 Sep 15 06:44 progressbar
drwxrwxr-x 2 kali kali 4096 Sep 15 06:44 statusbar
drwxrwxr-x 2 kali kali 4096 Sep 15 06:44 toolbar
drwxrwxr-x 2 kali kali 4096 Sep 15 06:44 toolpanel

./Configurations2/floater:
total 8
drwxrwxr-x 2 kali kali 4096 Sep 15 06:44 .
drwxrwxr-x 9 kali kali 4096 Sep 19 13:00 ..

./Configurations2/menubar:
total 8
drwxrwxr-x 2 kali kali 4096 Sep 15 06:44 .
drwxrwxr-x 9 kali kali 4096 Sep 19 13:00 ..

./Configurations2/popupmenu:
total 8
drwxrwxr-x 2 kali kali 4096 Sep 15 06:44 .
drwxrwxr-x 9 kali kali 4096 Sep 19 13:00 ..

./Configurations2/progressbar:
total 8
drwxrwxr-x 2 kali kali 4096 Sep 15 06:44 .
drwxrwxr-x 9 kali kali 4096 Sep 19 13:00 ..

./Configurations2/statusbar:
total 8
drwxrwxr-x 2 kali kali 4096 Sep 15 06:44 .
drwxrwxr-x 9 kali kali 4096 Sep 19 13:00 ..

./Configurations2/toolbar:
total 8
drwxrwxr-x 2 kali kali 4096 Sep 15 06:44 .
drwxrwxr-x 9 kali kali 4096 Sep 19 13:00 ..

./Configurations2/toolpanel:
total 8
drwxrwxr-x 2 kali kali 4096 Sep 15 06:44 .
drwxrwxr-x 9 kali kali 4096 Sep 19 13:00 ..

./META-INF:
total 12
drwxrwxr-x 2 kali kali 4096 Sep 19 13:00 .
drwxrwxr-x 5 kali kali 4096 Sep 19 13:00 ..
-rw-rw-r-- 1 kali kali 1068 Sep 15 06:44 manifest.xml

./Thumbnails:
total 24
drwxrwxr-x 2 kali kali  4096 Sep 19 13:00 .
drwxrwxr-x 5 kali kali  4096 Sep 19 13:00 ..
-rw-rw-r-- 1 kali kali 14845 Sep 15 06:44 thumbnail.png
```

after viewing the `mimetype` we can note that we are indeed dealing with a OpenDocument Spreadsheet (ODS), more specifically, and OASIS Open Document Format (ODF). These file type's can be viewed/edited using `LibreOffice Calc` and `OpenDocument Calc`. These file format's are represented as ZIP archive's containing several XML file that describe the document's sturcture, content styles, metadata etc.

[XML Namespace Document for OpenDocument Version 1.4 (oasis-open.org)](http://docs.oasis-open.org/ns/office/1.2/meta/odf#StylesFile)


However, after opening the database file using `LibreOffice Calc`, I realized how much data there was. I decided to use python and the `odfpy` library to parse the data into `pandas` dataFrame's to more easily sort the data by company name and dump to individual `.csv` file's containing any row's and cell data with the same company name, this way I am more easily able to identify discrepancies within the data to identify potential malicious orders.

here is my code to do so:
```python
#!/usr/bin/python3

import os
import pandas as pd
from odf.opendocument import load
from odf.table import Table, TableRow, TableCell
from odf.text import P

# Load the ODS document
doc = load("shipping.ods")

# Function to extract text from a cell
def get_cell_text(cell):
    paragraphs = cell.getElementsByType(P)
    text = ''
    for p in paragraphs:
        for node in p.childNodes:
            if node.nodeType == node.TEXT_NODE:
                text += node.data
    return text

# List to hold the parsed data
data = []

# Extract all tables and rows
for table in doc.getElementsByType(Table):
    print("Table:", table.getAttribute("name"))
    for row in table.getElementsByType(TableRow):
        row_data = []
        for cell in row.getElementsByType(TableCell):
            cell_text = get_cell_text(cell)
            row_data.append(cell_text)
        # Only append if the row has content
        if row_data:
            data.append(row_data)

# Convert the parsed data into a pandas DataFrame
# Adjust column names according to data structure
columns = ['Company', 'Address', 'Primary Contact', 'Primary Phone', 'Primary Email', 
           'Secondary Contact', 'Secondary Phone', 'Secondary Email', 'Order ID', 'Date']
df = pd.DataFrame(data, columns=columns)

# Create the directory 'company_info/' if it doesn't exist
output_dir = 'company_info'
if not os.path.exists(output_dir):
    os.makedirs(output_dir)

# Iterate over unique companies and save each to a separate CSV file
for company in df['Company'].unique():
    # Filter by company
    filtered_df = df[df['Company'] == company]
    
    # Sort the data by Order ID and Date for easier analysis
    sorted_df = filtered_df.sort_values(by=['Order ID', 'Date'])
    
    # Save the filtered and sorted data to a CSV file
    company_filename = os.path.join(output_dir, f'{company.replace(" ", "_")}.csv')
    sorted_df.to_csv(company_filename, index=False)
    
    print(f"Data for {company} saved to {company_filename}")

# Additional: Optional, print summary info
print("\nCSV files have been created for all companies and saved in the 'company_info/' directory.")
```

After running this code, we are able to `cd` into `company_info` and see all the individual `.csv` file's containing all order information from the database:

```bash
company_info $ ls 
Aegis_Defense_Solutions.csv        Sentinel_Security_Group.csv
Aerospace_Dynamics.csv             Springfield_Defense_Laboratories.csv
Atlas_Strategic_Systems.csv        Terraform_Industries.csv
Cerberus_Defense_Solutions.csv     Titan_Aerospace_Systems.csv
Guardian_Armaments.csv             Vanguard_Technologies.csv
Ironclad_Defense_Technologies.csv  Williams_Jackson_International.csv
Phoenix_Tactical_Innovations.csv
```

After inspecting these manually, we can not that it's the same contacts for all orders. So I manually went through all the `.csv` file's and tried to identify any order's with different addresses/contact information. In `Guardian_Arnaments.csv` we can quickly identify the line:
```
Guardian Armaments,"016 Peterson Manor, Watsonville, AR 82987",Chris Mcneil,###-###-7218,chris_52293@guard.ar,Jasper Wright,###-###-3160,jasper_0384@guard.ar,GUA1126378,2024-04-25
```

This uses a different address than all the other db entries for Guardian Armaments. This is likely the malicious order...


Submitting the order ID `GUA1126378` confirms this! 


