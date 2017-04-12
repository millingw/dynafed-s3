# dynafed-s3
The project aims to implement an s3 compatible gateway to dynafed

## Detailed aims
The dynafed software, produced by CERN, provides federation of different end storage types. It does not currently provide an s3-compatible interface. http://lcgdm.web.cern.ch/dynafed-dynamic-federation-project  
The aim of this project is to implement a lightweight gateway that will provide a subset of s3 operations on top of an existing dynafed installation, such that a client may use dynafed resources via standard s3 interfaces and not be aware of dynafed-specific information.

### Funding and organisation
This project is funded under EUDAT Horizion 2020, work package 9.1

