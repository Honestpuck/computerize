# computerize

Tools useful when migrating Jamf Pro computer records

`sanitise` will remove all personal information and replace it with random details

There is a problem when using Jamf Migrator to move computer records, it 
doesn't respect the management status so you end up with all computers
unmanaged. `managed.py` fixes this so that they are all managed again.
