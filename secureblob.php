<?php
/*
    secureblob.php https://github.com/moparisthebest/secureblob
    Copyright (C) 2014  moparisthebest (Travis Burtrum)

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU Affero General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Affero General Public License for more details.

    You should have received a copy of the GNU Affero General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/
global $blob_path, $tmp_blob_path, $new_blob_source, $default_content_type, $max_size, $min_size;
$blob_path = '/tmp/secureblob/';
$tmp_blob_path = '/run/shm/secureblob/';
$new_blob_source = '/dev/urandom';
//$new_blob_source = '/dev/zero';
//$new_blob_source = '/run/shm/bob';
$default_content_type = 'application/octet-stream';
//$max_size = 4 * 1024 * 1024; // 4mb
$max_size = 64 * 1024; // 64kb
$min_size = 16;

// params for my encrypt/decrypt/stretch_key functions, if you write your own functions, ignore these params
global $mcrypt_cipher, $mcrypt_mode, $mcrypt_rand_src, $pbkdf2_hash, $pbkdf2_iterations, $salt_length;
$mcrypt_cipher = MCRYPT_RIJNDAEL_128;
//$mcrypt_cipher = MCRYPT_RIJNDAEL_256;
//$mcrypt_cipher = MCRYPT_BLOWFISH;
$mcrypt_mode = MCRYPT_MODE_CBC;
$mcrypt_rand_src = MCRYPT_DEV_RANDOM;
$pbkdf2_hash = 'sha512';
$pbkdf2_iterations = 65536;
$salt_length = 32;

// todo: include config file

function encrypt($decrypted, $password) {
    global $mcrypt_cipher, $mcrypt_mode, $mcrypt_rand_src, $salt_length;
    //echo "decrypted: '$decrypted'<br/>\n";
    srand();
    // first generate a random $salt_length character salt
    $salt_chars = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ’"\'~!@#$%^&*(){}[],./?';
    $salt_chars_len = strlen($salt_chars);
    $salt = '';
    for ($i = 0; $i < $salt_length; $i++)
        $salt .= $salt_chars[rand(0, $salt_chars_len)];
    //echo "salt: '$salt'<br/>\n";
    // stretch the key
    $key = stretch_key($password, $salt, mcrypt_get_key_size($mcrypt_cipher, $mcrypt_mode));
    // Build $iv and $iv_base64.  We use a block size of 128 bits (AES compliant) and CBC mode.  (Note: ECB mode is inadequate as IV is not used.)
    $iv = mcrypt_create_iv(mcrypt_get_iv_size($mcrypt_cipher, $mcrypt_mode), $mcrypt_rand_src);
    $iv_base64 = base64_encode($iv);
    //echo "iv_base64: '$iv_base64'<br/>\n";
    // Encrypt $decrypted and an MD5 of $decrypted using $key.  MD5 is fine to use here because it's just to verify successful decryption.
    $encrypted = base64_encode(mcrypt_encrypt($mcrypt_cipher, $key, $decrypted . md5($decrypted), $mcrypt_mode, $iv));
    //echo "encrypted: '$encrypted'<br/>\n";
    // We're done!
    return "$salt:$mcrypt_cipher:$mcrypt_mode:$iv_base64:$encrypted";
}

function decrypt($encrypted, $password, $check_integrity = true) {
    $encrypted = explode(':', $encrypted); // salt, mcrypt_cipher, mcrypt_mode, iv_base64, encrypted_base64
    // retrieve $salt from $encrypted
    $salt = $encrypted[0];
    $mcrypt_cipher = $encrypted[1];
    $mcrypt_mode = $encrypted[2];
    // stretch the key
    $key = stretch_key($password, $salt, mcrypt_get_key_size($mcrypt_cipher, $mcrypt_mode));
    // Retrieve $iv which is base64_decoded.
    $iv = base64_decode($encrypted[3]);
    // Decrypt the data.  rtrim won't corrupt the data because the last 32 characters are the md5 hash; thus any \0 character has to be padding.
    $decrypted = rtrim(mcrypt_decrypt($mcrypt_cipher, $key, base64_decode($encrypted[4]), $mcrypt_mode, $iv), "\0\4");
    // Retrieve $hash which is the last 32 characters of $decrypted.
    $hash = substr($decrypted, -32);
    // Remove the last 32 characters from $decrypted.
    $decrypted = substr($decrypted, 0, -32);
    // Integrity check.  If this fails, either the data is corrupted, or the password/salt was incorrect.
    if ($check_integrity && md5($decrypted) != $hash) return false;
    // Yay!
    return $decrypted;
}
function stretch_key($key, $salt, $max_key_size){
    global $pbkdf2_hash, $pbkdf2_iterations;
    //echo "max_key_size: '$max_key_size'<br/>\n";
    //return hash('SHA256', $salt . $key, true);
    return pbkdf2($pbkdf2_hash, $key, $salt, $pbkdf2_iterations, $max_key_size, true);
}
function secure_delete_file($filename){
    $size = filesize($filename);

    $src = fopen('/dev/zero', 'rb');
    $dest = fopen($filename, 'wb');

    stream_copy_to_stream($src, $dest, $size);

    fclose($src);
    fclose($dest);
    unlink($filename);
}
function secure_delete_folder($path) {
    $it = new RecursiveIteratorIterator(
        new RecursiveDirectoryIterator($path),
        RecursiveIteratorIterator::CHILD_FIRST
    );
    foreach ($it as $file) {
        if (in_array($file->getBasename(), array('.', '..'))) {
            continue;
        } elseif ($file->isDir()) {
            rmdir($file->getPathname());
        } elseif ($file->isFile() || $file->isLink()) {
            secure_delete_file($file->getPathname());
        }
    }
    rmdir($path);
}
function write_to_file($fname, $contents, $mode = 'w') {
    $fh = fopen($fname, $mode);
    fwrite($fh, $contents);
    fclose($fh);
}
function encrypt_write($folder, $key, $decrypted = NULL, $fake = false){
    if($decrypted === NULL)
        $decrypted = create_blob();
    if(!file_exists($folder)) {
        // create directory
        mkdir($folder, 0700, true);
        // write attributes
        $failed_attempts = setDefaultLimits('failed-attempts', 0, 0, 3);
        $time_to_live = setDefaultLimits('time-to-live', 1, 1, 24);
        write_to_file($folder.'failed-attempts', 0);
        write_to_file($folder.'failed-attempts-limit', $failed_attempts);
        write_to_file($folder.'time-to-live', $time_to_live);
    }
    write_to_file($folder.($fake ? 'blobf' : 'blob'), encrypt($decrypted, $key), 'wb');
    return $decrypted;
}
// creates a blob from $new_blob_source
function create_blob(){
    global $new_blob_source, $max_size, $min_size;
    srand();
    return file_get_contents($new_blob_source, false, NULL, 0, rand( (($max_size-$min_size)/2), $max_size)); // size is some random amount between halfway between max_size and min_size and max_size
}
/*
 * PBKDF2 key derivation function as defined by RSA's PKCS #5: https://www.ietf.org/rfc/rfc2898.txt
 * $algorithm - The hash algorithm to use. Recommended: SHA256
 * $password - The password.
 * $salt - A salt that is unique to the password.
 * $count - Iteration count. Higher is better, but slower. Recommended: At least 1000.
 * $key_length - The length of the derived key in bytes.
 * $raw_output - If true, the key is returned in raw binary format. Hex encoded otherwise.
 * Returns: A $key_length-byte key derived from the password and salt.
 *
 * Test vectors can be found here: https://www.ietf.org/rfc/rfc6070.txt
 *
 * This implementation of PBKDF2 was originally created by https://defuse.ca
 * With improvements by http://www.variations-of-shadow.com
 */
function pbkdf2($algorithm, $password, $salt, $count, $key_length, $raw_output = false)
{
    $algorithm = strtolower($algorithm);
    if(!in_array($algorithm, hash_algos(), true))
        trigger_error('PBKDF2 ERROR: Invalid hash algorithm.', E_USER_ERROR);
    if($count <= 0 || $key_length <= 0)
        trigger_error('PBKDF2 ERROR: Invalid parameters.', E_USER_ERROR);

    if (function_exists("hash_pbkdf2")) {
        // The output length is in NIBBLES (4-bits) if $raw_output is false!
        if (!$raw_output) {
            $key_length = $key_length * 2;
        }
        return hash_pbkdf2($algorithm, $password, $salt, $count, $key_length, $raw_output);
    }

    $hash_length = strlen(hash($algorithm, "", true));
    $block_count = ceil($key_length / $hash_length);

    $output = "";
    for($i = 1; $i <= $block_count; $i++) {
        // $i encoded as 4 bytes, big endian.
        $last = $salt . pack("N", $i);
        // first iteration
        $last = $xorsum = hash_hmac($algorithm, $last, $password, true);
        // perform the other $count - 1 iterations
        for ($j = 1; $j < $count; $j++) {
            $xorsum ^= ($last = hash_hmac($algorithm, $last, $password, true));
        }
        $output .= $xorsum;
    }

    if($raw_output)
        return substr($output, 0, $key_length);
    else
        return bin2hex(substr($output, 0, $key_length));
}

function setRequired($name){
    if(!isset($_REQUEST[$name]))
        die("All parameters must be set."); // intentionally vague
    return $_REQUEST[$name];
}

function setDefault($name, $default){
    return isset($_REQUEST[$name]) ? $_REQUEST[$name] : $default;
}

// this function does no bounds checking on lower/upper, so don't send in user input
function setDefaultLimits($name, $default, $lower, $upper){
    $ret = setDefault($name, $default);
    if($ret < $lower)
        return $lower;
    if($ret > $upper)
        return $upper;
    return $ret;
}

$id = setRequired('id');
$key = setRequired('key');

$tmp = setDefault('tmp', true) !== 'false'; // default is true

$folder = ($tmp ? $tmp_blob_path : $blob_path).hash('sha512', $id).'/';

// I'd like the file to never get to the filesystem at all, any good solutions for this?
// http://stackoverflow.com/questions/5701508/storing-php-php-fpm-apaches-temporary-from-upload-files-in-ram-rather-than-th
$file = $_FILES['file'];

$decrypted = '';
if(isset($file)){
    // then we want to SET a new file that was sent in
    if($file['size'] > $max_size)
        die('Max file size exceeded');
    if($file['size'] < $min_size)
        die('Min file size not reached');

    $decrypted = file_get_contents($file['tmp_name']);

    // delete unencrypted file and previous folder if it exists
    secure_delete_file($file['tmp_name']);
    secure_delete_folder($folder);

    encrypt_write($folder, $key, $decrypted);

    //echo "serving new real just sent in<br />\n";
} else if(!file_exists($folder)) {
    // then we want to SET a new file we create from $new_blob_source
    $decrypted = encrypt_write($folder, $key);

    //echo "serving new real just generated<br />\n";
} else {
    // otherwise we want to serve an existing file
    $fname = $folder.'blob';
    $failed_attempts_file = $folder.'failed-attempts';
    $decrypted = decrypt(file_get_contents($fname), $key);
    if($decrypted === false) {
        $failed_attempts = (int)file_get_contents($failed_attempts_file) + 1;
        $failed_attempts_limit = (int)file_get_contents($folder.'failed-attempts-limit');
        if($failed_attempts >= $failed_attempts_limit){
            // delete this folder
            secure_delete_folder($folder);

            // create a new key, write it out, and serve it
            $decrypted = encrypt_write($folder, $key);

            //echo "serving new because failed_attempts reached<br />\n";
        } else {
            // write incremented $failed_attempts to file
            write_to_file($failed_attempts_file, $failed_attempts);
            // and serve the fake file
            $fname = $folder.'blobf';
            if(file_exists($fname)) {
                // serve existing fake file
                $decrypted = decrypt(file_get_contents($fname), $key, false);
                //echo "serving existing fake<br />\n";
            } else {
                // create fake file, serve it
                $decrypted = encrypt_write($folder, $key, NULL, true);
                //echo "serving new fake<br />\n";
            }
        }
    } else {
        // reset $failed_attempts_file
        write_to_file($failed_attempts_file, 0);
        //echo "serving real<br />\n";
    }
}

header('Content-Type: '.setDefault('content-type', $default_content_type));
echo $decrypted;
//echo "decrypted: '$decrypted'<br/>\n";
?>