#### Here is the idea:
  1. This script stores and returns binary blobs, so really, anything.
  2. Every blob has extra attributes which can be set by additional parameters on creation, these are:
    1. id (required), uniquely identifies each blob
    2. key (required), used to encrypt/decrypt blob on storage/access
    3. file, the blob to encrypt and store, ideally this is already encrypted with a local key that never leaves your computer before sent to this script.
    4. time-to-live (HOURS where 1 => time-to-live <= 24), if it hasn't been successfully accessed within X hours, all traces of it will be securely deleted (by a cronjob, not in PHP)
    5. tmp (true/false), stores the blob in in-memory storage, with the hope that if the machine is powered off everything disappears
    6. failed-attempts (where 0 >= failed-attempts <= 3), if requested id exists but provided key is wrong, increment a failed-attempts counter, if these ever equal each other, securely delete the blob, 0 means delete on the first failed attempt
  3. Sending in only an id and key will decrypt the blob and send it back to the browser, if nothing exists at that ID, a new blob will be created from $new_blob_source with sent in parameters or defaults, stored, and sent back.
  4. Sending in an id, key, and file will save (and overwrite if id was set before) the file to be served back when requested again, with optionally overridden defaults based on the other parameters sent in.
  5. Every time a blob is successfully accessed (correct id and key), the time will be saved, and failed-attempts will be reset. This will be used by the secure deleting cronjob.
  6. Every time a blob is accessed with an existing id but an incorrect key (decryption was unsuccessful), this will serve a 'fake' blob generated from $new_blob_source and stored with the $id on creation.  It will increment failed-attempts and possibly delete everything, going back to step 3.

I am looking for feedback on how *secure* this idea is, if there are flaws in the approach or potential weaknesses I don't see, and ways to improve it.

Any improvements that can be made in the reference implementations will be appreciated as well.

#### In this repo

  1. secureblob.php - Reference implementation in PHP
  2. secureblob_cron.sh - Reference implementation of cleaning cronjob
  3. secureblob_up.sh - Upload script to test reference implementations
  4. agpl-3.0.txt - License all code is released under
