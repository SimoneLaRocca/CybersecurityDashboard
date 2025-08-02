# Introduction
In the context of the growing prevalence of cyber threats, it is essential to develop tools capable of supporting the detection, classification, and analysis of cyberattacks and vulnerabilities.
This project was developed with the goal of creating an interactive dashboard for managing, querying, and correlating information related to malware and vulnerabilities (CVE – Common Vulnerabilities and Exposures), while also integrating external analysis through the public VirusTotal API.

## Application Context

The application is set within the field of cybersecurity, where analyzing large volumes of data related to malware and vulnerabilities (CVEs) is crucial. It enables users to:  
  •	Store and query structured data using MongoDB;  
	•	Correlate malware and CVEs to identify potential threats;  
	•	Send requests to the VirusTotal API for real-time analysis of suspicious IPs and files.  
 
The goal is to provide a decision-support tool for security analysts, offering a reliable and replicated system capable of operating even in the event of node failures.

## Miniworld Description
The modeled miniworld represents a simplified system for managing malware and CVEs.
The data comes from two reliable sources:  
	•	**Malware** records were extracted from the **UNSW-NB15 dataset**, developed by the **Cyber Range Lab at UNSW Canberra** (University of New South Wales). This dataset contains over 2 million simulated network connections, about 90,000 of which are labeled as attacks and divided into various categories (e.g., Exploits, Worms, Shellcode, Fuzzers, Backdoors, etc.). For this project, a meaningful subset of the data was selected, transformed, and adapted to MongoDB’s document-based format.  
	•	**Vulnerabilities (CVEs)** are sourced from the official database maintained by **NIST** (National Institute of Standards and Technology). Each CVE is identified by a unique ID (e.g., “CVE-2023-1234”) and is associated with metadata such as severity score (CVSS), technical description, and other structured information.
 
The two collections can be linked via the CVE identifier (e.g., CVE-2023-1234), allowing for correlation between malware samples and the vulnerabilities they exploit.

## Replica Set Configuration
To ensure high availability and fault tolerance, the MongoDB database was configured using a Replica Set consisting of three nodes. This architecture allows the system to remain operational even in the event of a node failure.
The configuration was **simulated locally**, using three mongod instances running on different ports of the same machine, each with separate data directories and log files. This setup enables a controlled simulation of a distributed cluster environment, useful for both educational and experimental purposes.
Below is the sequence of commands used to configure the replica set:

Create a separate directory for each MongoDB node:
```cmd
md "c:\data\rs1" "c:\data\rs2" "c:\data\rs3"
```
Import datasets into MongoDB:
```cmd
mongoimport --db cybersecurity --collection cve --file "C:\\path\\to\\cve.json" --jsonArray
mongoimport --db cybersecurity --collection malware --type csv --headerline --file "C:\\path\\to\\malware.csv"
```
Launch three mongod instances in separate terminals (one per node):
```cmd
mongod --replSet rs0 --dbpath "C:\data\rs1" --port 27017 
mongod --replSet rs0 --dbpath "C:\data\rs2" --port 27018 
mongod --replSet rs0 --dbpath "C:\data\rs3" --port 27019
```

Open a new terminal to connect to the first node and initialize the replica set:
```cmd
mongosh --port 27017
```

Create the replica set configuration:
```cmd
rsconf = {
  _id: "rs0",
  members: [
    { _id: 0, host: "localhost:27017" },
    { _id: 1, host: "localhost:27018" },
    { _id: 2, host: "localhost:27019" }
  ]
}
```

Initialize the replica set:
```cmd
rs.initiate(rsconf)
```

Check replica set status:
```cmd
rs.status()
```

## References
- [Cloud folder with demos and datasets](https://drive.google.com/drive/folders/1MbjbKNSVO2zpG4jqCz-5ZAM7hp-PIu6n?usp=sharing)  
- [NIST dataset](https://nvd.nist.gov/vuln/data-feeds)  
- [UNSW-NB15 dataset](https://research.unsw.edu.au/projects/unsw-nb15-dataset)  
- Textbook used for environment setup (chapter 10):  
  "MongoDB. The Definitive Guide: Powerful and Scalable Data Storage" by Shannon Bradshaw, Eoin Brazil, and Kristina Chodorow.
