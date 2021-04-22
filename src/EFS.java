import java.io.ByteArrayOutputStream;
import java.io.File;

import java.nio.ByteBuffer;

import java.util.Arrays;

/**
 * @author Joseph Norman
 * @netid jsn180000
 * @email jsn180000@utdallas.edu
 */
public class EFS extends Utility {
    public static final int IV_SIZE = 12; // bytes
    public static final int MAC_SIZE = 512 / 8; // bytes
    public static final int MAC_LINES = MAC_SIZE / 16; // lines
    public static final int MAC_ED_BLOCK_SIZE = 1024 - MAC_SIZE; // bytes
    public static final int MAC_ED_BLOCK_LINES = MAC_ED_BLOCK_SIZE / 16; // lines

    private static byte[] endOfMeta = new String("ENDOFMETA").getBytes(); 

    public EFS(Editor e) {
        super(e);
        set_username_password();
        //username = "joseph";
        //password = "password";
    }

   
    /**
     * Steps to consider... <p>
     *  - add padded username and password salt to header <p>
     *  - add password hash and file length to secret data <p>
     *  - AES encrypt padded secret data <p>
     *  - add header and encrypted secret data to metadata <p>
     *  - compute HMAC for integrity check of metadata <p>
     *  - add metadata and HMAC to metadata file block <p>
     */
    @Override
    public void create(String file_name, String user_name, String password) throws Exception {
        byte[] passwordSalt = secureRandomNumber(10);
        byte[] initializationVector = secureRandomNumber(IV_SIZE);

        updateMetadata(file_name, user_name, password, 0, passwordSalt, initializationVector);
    }

    private void updateMetadata(String file_name, String user_name, String password, int length, byte[] passwordSalt, byte[] initializationVector) throws Exception {
        // password information
        ByteArrayOutputStream saltedPasswordStream = new ByteArrayOutputStream();
        saltedPasswordStream.write(passwordSalt);
        saltedPasswordStream.write(password.getBytes());
        byte[] saltedPassword = saltedPasswordStream.toByteArray();

        // hashed password and the keys generated from the hash
        byte[] passwordHash = getPasswordHash(saltedPassword);
        byte[] keyHMAC = getHMACKey(saltedPassword);
        byte[] keyAES = getAESKey(saltedPassword);

        // header information
        ByteArrayOutputStream fileOutput = new ByteArrayOutputStream();
        fileOutput.write((user_name).getBytes()); // username
        fileOutput.write(0x0a);
        fileOutput.write(passwordSalt); // password salt
        fileOutput.write(0x00);
        pad(fileOutput, 16); // end of header

        byte[] lengthArray = new byte[8];

        String formattedLength = String.format("%1$" + 8 + "s", length).replace(' ', '0');

        // metadata
        ByteArrayOutputStream metadata = new ByteArrayOutputStream();
        metadata.write(passwordHash); // password hash
        metadata.write(0x0a);
        metadata.write(formattedLength.getBytes()); // length of document
        metadata.write(0x0a);
        metadata.write(initializationVector); // length of document
        pad(metadata, 16);

        byte[] encryptedMetadata = encript_AES(metadata.toByteArray(), keyAES);

        // write encrypted metadata to the file
        fileOutput.write(encryptedMetadata);

        // fileOutput.write(metadata.toByteArray());
        fileOutput.write(0x00);
        pad(fileOutput, 16);

        byte[] metadataHMAC = hmac(keyHMAC, encryptedMetadata);
        fileOutput.write(metadataHMAC);
        pad(fileOutput, 16);

        // write encrypted metadata to file output
        pad(fileOutput, Config.BLOCK_SIZE);
        byte[] toWrite = fileOutput.toByteArray();

        // initializing the meta files
        dir = new File(file_name);
        dir.mkdirs();
        File meta = new File(dir, "0");
        save_to_file(toWrite, meta);
    }
    /**
     * Steps to consider... <p>
     *  - check if metadata file size is valid <p>
     *  - get username from metadata <p>
     */
    @Override
    public String findUser(String file_name) throws Exception {
        File file = new File(file_name);
        File meta = new File(file, "0");

        byte[] contents = read_from_file(meta);

        if(contents.length != Config.BLOCK_SIZE)
            throw new Exception();
        else {
            ByteArrayOutputStream user = new ByteArrayOutputStream();

            for(int i = 0; i < contents.length; i ++) {
                if(contents[i] == 0x0a)
                    break;
                else
                    user.write(contents[i]);
            }
            return byteArray2String(user.toByteArray());
        }
    }

    /**
     * Steps to consider...:<p>
     *  - get password, salt then AES key <p>     
     *  - decrypt password hash out of encrypted secret data <p>
     *  - check the equality of the two password hash values <p>
     *  - decrypt file length out of encrypted secret data
     */
    @Override
    public int length(String file_name, String password) throws Exception {
        File file = new File(file_name);
        File metaFile = new File(file, "0");

        byte[] contents = read_from_file(metaFile);

        ByteArrayOutputStream saltedPasswordStream = new ByteArrayOutputStream();

        // first pass the visible header
        int i = 0;
        boolean passedName = false;
        for(i = i; i < contents.length; i ++) {
            if(passedName) {
                if(contents[i] == 0x00)
                    break;
                saltedPasswordStream.write(contents[i]);
            }
            else {
                if(contents[i] == 0x0a)
                    passedName = true;
            }
        }
        saltedPasswordStream.write(password.getBytes());

        for(i = i; i < contents.length; i ++) {
            if(contents[i] != 0x00)
                break;
        }

        int startOfMeta = i;

        ByteArrayOutputStream secretMetaStream = new ByteArrayOutputStream();
        for(i = i; i < startOfMeta + 64; i ++) { // length of password hash 16, length 8, and IV 12 == 36
            secretMetaStream.write(contents[i]);
        }

        byte[] secretMeta = secretMetaStream.toByteArray();
        byte[] keyAES = getAESKey(saltedPasswordStream.toByteArray());
        byte[] meta = decript_AES(secretMeta, keyAES);
        // byte[] meta = secretMeta;

        ByteArrayOutputStream passwordHashStream = new ByteArrayOutputStream();
        ByteArrayOutputStream lengthStream = new ByteArrayOutputStream();

        boolean finishedPasswordHash = false;
        for(int j = 0; j < meta.length; j ++) {
            if(finishedPasswordHash) {
                if(meta[j] == 0x0a)
                    break;
                lengthStream.write(meta[j]);
            }
            else {
                if(meta[j] == 0x0a)
                    finishedPasswordHash = true;
                else
                    passwordHashStream.write(meta[j]);
            }
        }

        byte[] passwordHash = passwordHashStream.toByteArray();
        byte[] length = lengthStream.toByteArray();

        if(Arrays.equals(passwordHash, getPasswordHash(saltedPasswordStream.toByteArray()))) {
            return Integer.parseInt(byteArray2String(length));
        }
        else throw new PasswordIncorrectException();
    }

    /**
     * Steps to consider...:<p>
     *  - verify password <p>
     *  - check check if requested starting position and length are valid <p>
     *  - decrypt content data of requested length 
     */
    @Override
    public byte[] read(String file_name, int starting_position, int len, String password) throws Exception {
    	File root = new File(file_name);

        int fileLength = length(file_name, password); // if password incorrect, exception thrown
        byte[] initializationVector = fetchInitializationVector(file_name, password);
        byte[] username = fetchUsername(file_name);
        byte[] passwordSalt = fetchPasswordSalt(file_name);

        ByteArrayOutputStream saltedPasswordStream = new ByteArrayOutputStream();
        saltedPasswordStream.write(passwordSalt);
        saltedPasswordStream.write(password.getBytes());

        byte[] aesKey = getAESKey(saltedPasswordStream.toByteArray());

        if(starting_position + len > fileLength) {
            throw new Exception();
        }

        int startBlock = starting_position / MAC_ED_BLOCK_SIZE;
        int endBlock = (starting_position + len) / MAC_ED_BLOCK_SIZE;

        ByteArrayOutputStream contentStream = new ByteArrayOutputStream();

        for(int file_i = startBlock + 1; file_i <= endBlock + 1; file_i ++) {
            byte[] blockContents = Arrays.copyOfRange(read_from_file(new File(root, Integer.toString(file_i))), MAC_SIZE, Config.BLOCK_SIZE);

            for(int line_i = 0; line_i < MAC_ED_BLOCK_LINES; line_i ++) {
                int counter = line_i + (file_i - 1) * MAC_ED_BLOCK_LINES;

                byte[] cipherText = Arrays.copyOfRange(blockContents, line_i * 16, (line_i + 1) * 16);
                byte[] plainText = decript_AESCTR(cipherText, aesKey, initializationVector, counter);

                int ending_position = starting_position + len;
                boolean ended = false;

                if(counter < starting_position / 16) 
                    plainText = new byte[0];
                else if(counter == starting_position / 16) { // the starting line
                    plainText = Arrays.copyOfRange(plainText, starting_position - ((starting_position / 16) * 16), plainText.length);
                }
                else if(counter > starting_position / 16 && counter < ending_position / 16)
                    plainText = plainText;
                else if(counter == (ending_position) / 16) { // ending line
                    plainText = Arrays.copyOfRange(plainText, 0, ending_position - ((ending_position / 16) * 16));
                }
                else {
                    plainText = new byte[0];
                }

                for(int i = 0; i < plainText.length; i ++) {
                    if(plainText[i] != 0x00)
                        contentStream.write(plainText[i]);
                }
                if(ended) break;
            }
        }
        return contentStream.toByteArray();
    }

    
    /**
     * Steps to consider...:<p>
	 *	- verify password <p>
     *  - check check if requested starting position and length are valid <p>
     *  - ### main procedure for update the encrypted content ### <p>
     *  - compute new HMAC and update metadata 
     */
    @Override
    public void write(String file_name, int starting_position, byte[] content, String password) throws Exception {
        File root = new File(file_name);

        int fileLength = length(file_name, password); //throws exception on incorrect password
        byte[] initializationVector = fetchInitializationVector(file_name, password);
        byte[] username = fetchUsername(file_name);
        byte[] passwordSalt = fetchPasswordSalt(file_name);

        ByteArrayOutputStream saltedPasswordStream = new ByteArrayOutputStream();
        saltedPasswordStream.write(passwordSalt);
        saltedPasswordStream.write(password.getBytes());

        byte[] aesKey = getAESKey(saltedPasswordStream.toByteArray());
        byte[] hmacKey = getHMACKey(saltedPasswordStream.toByteArray());

        if(starting_position > fileLength) {
            throw new Exception();
        }

        int len = content.length;
        int startBlock = starting_position / MAC_ED_BLOCK_SIZE;
        int endBlock = (starting_position + len) / MAC_ED_BLOCK_SIZE;

        for(int file_i = startBlock + 1; file_i <= endBlock + 1; file_i ++) {
            ByteArrayOutputStream plainFileOutputStream = new ByteArrayOutputStream();

            int contentStartIndex = (file_i - 1) * MAC_ED_BLOCK_SIZE - starting_position;
            int contentEndIndex = (file_i) * MAC_ED_BLOCK_SIZE - starting_position;
            byte[] prefix = new byte[0];
            byte[] suffix = new byte[0];

            // determine if there's anything before hand on the same block that needs to be written again
            if(file_i == startBlock + 1 && starting_position != startBlock * MAC_ED_BLOCK_SIZE) {
                byte[] blockContents = Arrays.copyOfRange(read_from_file(new File(root, Integer.toString(file_i))), MAC_SIZE, Config.BLOCK_SIZE);

                ByteArrayOutputStream decryptedPrefix = new ByteArrayOutputStream();

                for(int line_i = 0; line_i < MAC_ED_BLOCK_LINES; line_i ++) {
                    int counter = line_i + (file_i - 1) * MAC_ED_BLOCK_LINES;

                    byte[] cipherText = Arrays.copyOfRange(blockContents, line_i * 16, (line_i + 1) * 16);
                    decryptedPrefix.write(decript_AESCTR(cipherText, aesKey, initializationVector, counter)); // decript...
                    //decryptedPrefix.write(cipherText);
                }
                byte[] plainText = decryptedPrefix.toByteArray();
                prefix = Arrays.copyOfRange(plainText, 0, starting_position - startBlock * MAC_ED_BLOCK_SIZE);  

                contentStartIndex = Math.max(contentStartIndex, 0);
            }

            // then determine if there's anything afterhand on the same block that needs to be written again
            if(file_i == endBlock + 1) {
                File end = new File(root, Integer.toString(file_i));

                if(end.isFile()) {
                    byte[] blockContents = Arrays.copyOfRange(read_from_file(new File(root, Integer.toString(file_i))), MAC_SIZE, Config.BLOCK_SIZE);

                    ByteArrayOutputStream decryptedSuffix = new ByteArrayOutputStream();

                    for(int line_i = 0; line_i < MAC_ED_BLOCK_LINES; line_i ++) {
                        int counter = line_i + (file_i - 1) * MAC_ED_BLOCK_LINES;

                        byte[] cipherText = Arrays.copyOfRange(blockContents, line_i * 16, (line_i + 1) * 16);
                        decryptedSuffix.write(decript_AESCTR(cipherText, aesKey, initializationVector, counter));
                        //decryptedSuffix.write(cipherText);
                    }
                    byte[] plainText = decryptedSuffix.toByteArray();
                    suffix = Arrays.copyOfRange(plainText, starting_position + len - endBlock * MAC_ED_BLOCK_SIZE, plainText.length);
                }
                contentEndIndex = Math.min(contentEndIndex, len);
            }

            //fileOutputStream.write(new byte[MAC_SIZE]);
            plainFileOutputStream.write(prefix);
            plainFileOutputStream.write(Arrays.copyOfRange(content, contentStartIndex, contentEndIndex));
            plainFileOutputStream.write(suffix);
            pad(plainFileOutputStream, Config.BLOCK_SIZE);

            byte[] plainFileOutput = plainFileOutputStream.toByteArray();

            ByteArrayOutputStream encryptedFileOutputStream = new ByteArrayOutputStream();

            for(int line_i = 0; line_i < MAC_ED_BLOCK_LINES; line_i ++) {
                int counter = line_i + (file_i - 1) * MAC_ED_BLOCK_LINES;

                byte[] plainText = Arrays.copyOfRange(plainFileOutput, line_i * 16, (line_i + 1) * 16);
                encryptedFileOutputStream.write(encript_AESCTR(plainText, aesKey, initializationVector, counter));
                //encryptedFileOutputStream.write(plainText);
            }

            ByteArrayOutputStream fileOutputStream = new ByteArrayOutputStream();
            fileOutputStream.write(hmac(hmacKey, encryptedFileOutputStream.toByteArray())); // insert MAC here
            fileOutputStream.write(encryptedFileOutputStream.toByteArray());

            save_to_file(fileOutputStream.toByteArray(), new File(root, Integer.toString(file_i)));
        }

        int newLength = (starting_position + len) > fileLength ? (starting_position + len) : fileLength;

        // update metadata
        updateMetadata(file_name, byteArray2String(username), password, newLength, passwordSalt, initializationVector);
    }

    /**
     * Steps to consider...:<p>
  	 *  - verify password <p>
     *  - check the equality of the computed and stored HMAC values for metadata and physical file blocks<p>
     */
    @Override
    public boolean check_integrity(String file_name, String password) throws Exception {
        // first check metadata
        File root = new File(file_name);
        File metaFile = new File(root, "0");

        int fileLength = length(file_name, password); //throws exception on incorrect password
        byte[] passwordSalt = fetchPasswordSalt(file_name);

        ByteArrayOutputStream saltedPasswordStream = new ByteArrayOutputStream();
        saltedPasswordStream.write(passwordSalt);
        saltedPasswordStream.write(password.getBytes());

        byte[] hmacKey = getHMACKey(saltedPasswordStream.toByteArray());

        byte[] contents = read_from_file(metaFile);
        int i = 0;
        for(i = i; i < contents.length; i ++) {
            if(contents[i] == 0x00)
                break;
        }
        for(i = i; i < contents.length; i ++) {
            if(contents[i] != 0x00)
                break;
        }
        int startOfMeta = i;
        ByteArrayOutputStream secretMetaStream = new ByteArrayOutputStream();
        for(i = i; i < startOfMeta + 64; i ++) { // length of password hash 16, length 8, and IV 12 == 36
            secretMetaStream.write(contents[i]);
        }
        for(i = i; i < contents.length; i ++) {
            if(contents[i] != 0x00)
                break;
        }

        int startOfHMAC = i;

        ByteArrayOutputStream metadataHMACStream = new ByteArrayOutputStream();
        for(i = i; i < startOfHMAC + 64; i ++) {
            metadataHMACStream.write(contents[i]);
        }

        if(!Arrays.equals(metadataHMACStream.toByteArray(), hmac(hmacKey, secretMetaStream.toByteArray())))
            return false;

        // otherwise continue to each file
        int startBlock = 0;
        int endBlock = fileLength / MAC_ED_BLOCK_SIZE;

        for(int file_i = startBlock + 1; file_i <= endBlock + 1; file_i ++) {
            File block = new File(root, Integer.toString(file_i));

            byte[] blockHMAC = Arrays.copyOfRange(read_from_file(block), 0, MAC_SIZE);
            byte[] blockContents = Arrays.copyOfRange(read_from_file(block), MAC_SIZE, Config.BLOCK_SIZE);

            if(!Arrays.equals(blockHMAC, hmac(hmacKey, blockContents)))
                return false;
        }
        return true;
    }

    /**
     * Steps to consider... <p>
     *  - verify password <p>
     *  - truncate the content after the specified length <p>
     *  - re-pad, update metadata and HMAC <p>
     */
    @Override
    public void cut(String file_name, int length, String password) throws Exception {
        File root = new File(file_name);

        int fileLength = length(file_name, password);
        byte[] initializationVector = fetchInitializationVector(file_name, password);
        byte[] username = fetchUsername(file_name);
        byte[] passwordSalt = fetchPasswordSalt(file_name);

        ByteArrayOutputStream saltedPasswordStream = new ByteArrayOutputStream();
        saltedPasswordStream.write(passwordSalt);
        saltedPasswordStream.write(password.getBytes());

        byte[] aesKey = getAESKey(saltedPasswordStream.toByteArray());
        byte[] hmacKey = getHMACKey(saltedPasswordStream.toByteArray());

        int startBlock = length / MAC_ED_BLOCK_SIZE;

        // first repair the current block
        File startFile = new File(root, Integer.toString(startBlock + 1));            
        byte[] blockContents = Arrays.copyOfRange(read_from_file(startFile), MAC_SIZE, Config.BLOCK_SIZE);

        ByteArrayOutputStream startFileOutputStream = new ByteArrayOutputStream();

        for(int line_i = 0; line_i < MAC_ED_BLOCK_LINES; line_i ++) {
            byte[] lineContents = Arrays.copyOfRange(blockContents, line_i * 16, (line_i + 1) * 16); // of the line
            int counter = line_i + (startBlock) * MAC_ED_BLOCK_LINES;

            if(line_i == length / 16) { // THE line
                byte[] decryptedLine = decript_AESCTR(lineContents, aesKey, initializationVector, counter);
                //byte[] decryptedLine = lineContents;

                int lineLengthIndex = length - ((length / 16) * 16);

                ByteArrayOutputStream cutLineStream = new ByteArrayOutputStream();
                cutLineStream.write(Arrays.copyOfRange(decryptedLine, 0, lineLengthIndex));
                cutLineStream.write(new byte[16 - lineLengthIndex]);

                startFileOutputStream.write(encript_AESCTR(cutLineStream.toByteArray(), aesKey, initializationVector, counter));
                //startFileOutputStream.write(cutLineStream.toByteArray());
            }
            else if(line_i < length / 16) { // before
                startFileOutputStream.write(lineContents);
            }
            else { // after
                startFileOutputStream.write(encript_AESCTR(new byte[16], aesKey, initializationVector, counter));
            }
        }

        ByteArrayOutputStream metaStartFileOutputStream = new ByteArrayOutputStream();
        metaStartFileOutputStream.write(hmac(hmacKey, startFileOutputStream.toByteArray())); // update meta
        metaStartFileOutputStream.write(startFileOutputStream.toByteArray());

        save_to_file(metaStartFileOutputStream.toByteArray(), startFile);

        int file_i = startBlock + 2;
        while(true) {
            File nextFile = new File(root, Integer.toString(file_i));

            if(!nextFile.isFile())
                break;
            else
                nextFile.delete();

            file_i ++;
        }

        updateMetadata(file_name, byteArray2String(username), password, length, passwordSalt, initializationVector);
    }

    // IV_SIZE byte IV, 
    private byte[] encript_AESCTR(byte[] plainText, byte[] key, byte[] initializationVector, int counter) throws Exception {
        ByteArrayOutputStream encryptionInput = new ByteArrayOutputStream();
        encryptionInput.write(initializationVector);
        encryptionInput.write(ByteBuffer.allocate(4).putInt(counter).array()); // concat IV and counter

        byte[] encryptedIVCounter = encript_AES(encryptionInput.toByteArray(), key);

        ByteArrayOutputStream cipherTextStream = new ByteArrayOutputStream();

        for(int i = 0; i < encryptedIVCounter.length; i ++) {
            cipherTextStream.write((byte) encryptedIVCounter[i] ^ plainText[i]);
        }
        return cipherTextStream.toByteArray();
    }

    private byte[] decript_AESCTR(byte[] cipherText, byte[] key, byte[] initializationVector, int counter) throws Exception {
        ByteArrayOutputStream encryptionInput = new ByteArrayOutputStream();
        encryptionInput.write(initializationVector);
        encryptionInput.write(ByteBuffer.allocate(4).putInt(counter).array());

        byte[] encryptedIVCounter = encript_AES(encryptionInput.toByteArray(), key);

        ByteArrayOutputStream plainTextStream = new ByteArrayOutputStream();

        for(int i = 0; i < encryptedIVCounter.length; i ++) {
            plainTextStream.write((byte) encryptedIVCounter[i] ^ cipherText[i]);
        }
        return plainTextStream.toByteArray();
    }

    private byte[] fetchInitializationVector(String file_name, String password) throws Exception {
        File file = new File(file_name);
        File metaFile = new File(file, "0");

        byte[] contents = read_from_file(metaFile);

        ByteArrayOutputStream saltedPasswordStream = new ByteArrayOutputStream();

        // first pass the visible header
        int i = 0;
        boolean passedName = false;
        for(i = i; i < contents.length; i ++) {
            if(passedName) {
                if(contents[i] == 0x00)
                    break;
                saltedPasswordStream.write(contents[i]);
            }
            else {
                if(contents[i] == 0x0a)
                    passedName = true;
            }
        }
        saltedPasswordStream.write(password.getBytes());

        for(i = i; i < contents.length; i ++) {
            if(contents[i] != 0x00)
                break;
        }

        int startOfMeta = i;

        ByteArrayOutputStream secretMetaStream = new ByteArrayOutputStream();
        for(i = i; i < startOfMeta + 64; i ++) { // length of password hash 16, length 8, and IV 12 == 36
            secretMetaStream.write(contents[i]);
        }

        byte[] secretMeta = secretMetaStream.toByteArray();
        byte[] keyAES = getAESKey(saltedPasswordStream.toByteArray());
        byte[] meta = decript_AES(secretMeta, keyAES);
        // byte[] meta = secretMeta;

        ByteArrayOutputStream passwordHashStream = new ByteArrayOutputStream();
        ByteArrayOutputStream lengthStream = new ByteArrayOutputStream();
        ByteArrayOutputStream initializationVectorStream = new ByteArrayOutputStream();

        boolean finishedPasswordHash = false;
        boolean finishedLength = false;
        for(int j = 0; j < meta.length; j ++) {
            if(finishedPasswordHash && !finishedLength) {
                if(meta[j] == 0x0a)
                    finishedLength = true;
                lengthStream.write(meta[j]);
            }
            else if(!finishedPasswordHash) {
                if(meta[j] == 0x0a)
                    finishedPasswordHash = true;
                else
                    passwordHashStream.write(meta[j]);
            }
            else if(finishedPasswordHash && finishedLength) {
                if(meta[j] == 0x00)
                    break;
                else
                    initializationVectorStream.write(meta[j]);
            }
        }

        byte[] passwordHash = passwordHashStream.toByteArray();
        byte[] initializationVector = initializationVectorStream.toByteArray();

        if(Arrays.equals(passwordHash, getPasswordHash(saltedPasswordStream.toByteArray()))) {
            return initializationVector;
        }
        else throw new PasswordIncorrectException();
    }

    private byte[] fetchPasswordSalt(String file_name) throws Exception {
        File file = new File(file_name);
        File metaFile = new File(file, "0");

        byte[] contents = read_from_file(metaFile);

        ByteArrayOutputStream saltStream = new ByteArrayOutputStream();
        boolean passedName = false;
        for(int i = 0; i < contents.length; i ++) {
            if(!passedName) {
                if(contents[i] == 0x0a)
                    passedName = true;
            }
            else {
                if(contents[i] == 0x00)
                    break;
                saltStream.write(contents[i]);
            }
        }
        return saltStream.toByteArray();
    }

    private byte[] fetchUsername(String file_name) throws Exception {
        File file = new File(file_name);
        File metaFile = new File(file, "0");

        byte[] contents = read_from_file(metaFile);

        ByteArrayOutputStream usernameStream = new ByteArrayOutputStream();
        for(int i = 0; i < contents.length; i ++) {
            if(contents[i] == 0x0a)
                break;
            usernameStream.write(contents[i]);
        }
        return usernameStream.toByteArray();
    }

    private byte[] getPasswordHash(byte[] saltedPassword) throws Exception {
        return hash_SHA256(saltedPassword);
    }

    private byte[] getAESKey(byte[] saltedPassword) throws Exception {
        byte[] passwordHash = hash_SHA256(saltedPassword);
        return Arrays.copyOfRange(passwordHash, 0, passwordHash.length / 2);
    }

    private byte[] getHMACKey(byte[] saltedPassword) throws Exception {
        byte[] passwordHash = hash_SHA256(saltedPassword);
        return Arrays.copyOfRange(passwordHash, passwordHash.length / 2, passwordHash.length);
    }

    private static void pad(ByteArrayOutputStream stream, int size) {
        while(stream.size() % size != 0)
            stream.write(0x00);
    }

    private static byte[] hmac(byte[] key, byte[] message) throws Exception { // 128 bit key
        ByteArrayOutputStream oKeyPad = new ByteArrayOutputStream();
        ByteArrayOutputStream iKeyPad = new ByteArrayOutputStream();

        for(int i = 0; i < key.length; i ++) {
            oKeyPad.write((byte)(key[i] ^ 0x5c));
            iKeyPad.write((byte)(key[i] ^ 0x36));
        }

        ByteArrayOutputStream toInnerHash = new ByteArrayOutputStream();
        toInnerHash.write(iKeyPad.toByteArray());
        toInnerHash.write(message);

        byte[] innerHash = hash_SHA512(toInnerHash.toByteArray()); // MAC_SIZE * 8 bits

        ByteArrayOutputStream toOuterHash = new ByteArrayOutputStream();
        toOuterHash.write(oKeyPad.toByteArray());
        toOuterHash.write(innerHash);

        byte[] outerHash = hash_SHA512(toOuterHash.toByteArray()); // MAC_SIZE * 8 bits

        return outerHash;
    }
}
