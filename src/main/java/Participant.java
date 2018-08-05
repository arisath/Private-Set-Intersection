import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.digest.DigestUtils;
import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidParameterSpecException;
import java.util.ArrayList;
import java.util.Arrays;

/**
 * The Participant class represents an entity participating
 * in the private set intersection scheme
 */
public abstract class Participant
{
    /**
     * Returns the name of the entry
     * @param line
     * @return
     * @throws IOException
     */
    static String getName(String line) throws IOException
    {
        String[] entry = line.split(" ");

        String name = (entry[0]);

        return name;
    }

    /**
     * Returns the output of the SHA-1 hash function over the input
     * @param input
     * @return
     */
    static String sha1Hash(String input)
    {
        String digest = DigestUtils.sha1Hex(input);

        return digest;
    }

    /**
     * Returns the output of the MD5 hash function over the input
     * @param input
     * @return
     */
    static String md5Hash(String input)
    {
        String digest = DigestUtils.md5Hex(input);

        return digest;

    }

}

/**
 * Represents the server participating in the private set intersection scheme
 * The server hash a list of entries, each entry includes a name and some data
 * The server wants to inform the client about entries they have in common and their associated data,
 * but without revealing to the client any entries outside the intersection
 */
class Server extends Participant
{
    /**
     * Returns the data associated with an entry
     * @param line
     * @return
     * @throws IOException
     */
    static String getAssociatedData(String line) throws IOException
    {
        String[] entry = line.split(" ");

        String associatedData = entry[1];

        return associatedData;
    }

    /**
     * Returns an arraylist of type Entry with all the entries included
     * in the input file
     * @param filename
     * @return
     * @throws IOException
     */
    static ArrayList<Entry> getEntries(String filename) throws IOException
    {
        BufferedReader br = null;

        try
        {
            ClassLoader classloader = Thread.currentThread().getContextClassLoader();

            InputStream is = classloader.getResourceAsStream(filename);

            br = new BufferedReader(new InputStreamReader(is));

            ArrayList<Entry> entries = new ArrayList<Entry>();

            String line;

            while ((line = br.readLine()) != null)
            {
                String name = getName(line);

                String md5 = md5Hash(name);

                String sha1 = sha1Hash(name);

                String data = getAssociatedData(line);

                Entry entry = new Entry(md5, sha1, data);

                entries.add(entry);
            }
            return entries;
        }
        catch (FileNotFoundException e)
        {
            System.out.println("File not found");
        }
        finally
        {
            br.close();
        }
        return null;
    }

    /**
     * Encrypts the associated data of the input entry with AES-128 in CBC mode
     * using the output of the MD5 hash function over the name of the entry as the key
     * Computes the H-MAC over the encrypted associated data using the output of the
     * MD5 hash function over the name of the entry as the key
     * @param entry
     * @return
     */
    static Entry encryptAndHmac(Entry entry)
    {
        try
        {
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");

            IvParameterSpec spec = cipher.getParameters().getParameterSpec(IvParameterSpec.class);

            byte[] initializationVector = spec.getIV();

            IvParameterSpec iv = new IvParameterSpec(initializationVector);

            String md5name = entry.getMd5();

            byte[] aesKey = md5name.getBytes("UTF-8"); //key

            byte[] str = entry.getData().getBytes("UTF-8");   //plaintext

            SecretKeySpec key = new SecretKeySpec(aesKey, "AES");

            cipher.init(Cipher.ENCRYPT_MODE, key, iv);

            byte[] ciphertext = cipher.doFinal(str);

            byte[] encryptedByteValue = new Base64().encode(ciphertext);

            String encryptedValue = new String(encryptedByteValue);

            entry.setIV(initializationVector);

            entry.setData(encryptedValue);

            byte[] hmac = computeHmac(entry);

            entry.setHmac(hmac);

            entry.setName(null);

            return entry;
        }
        catch (NoSuchAlgorithmException e)
        {
            System.out.println("Invalid encryption algorithm");
        }
        catch (NoSuchPaddingException e)
        {
            System.out.println("Invalid padding selection");
        }
        catch (InvalidParameterSpecException e)
        {
            System.out.println("Invalid parameters selected");
        }
        catch (InvalidAlgorithmParameterException e)
        {
            System.out.println("Invalid algorithm parameters");
        }
        catch (InvalidKeyException e)
        {
            System.out.println("Invalid key");
        }
        catch (IllegalBlockSizeException e)
        {
            System.out.println("Illegal block size");
        }
        catch (BadPaddingException e)
        {
            System.out.println("Invalid padding specified");
        }
        catch (UnsupportedEncodingException e)
        {
            System.out.println("The encoding is not supported");
        }
        return null;
    }

    /**
     * Computes the H-MAC over the encrypted associated data of the input entry
     * using the output of the MD5 hash function over the name of the entry as the key
     * @param encryptedEntry
     * @return
     */
    static byte[] computeHmac(Entry encryptedEntry)
    {
        try
        {
            Mac mac = Mac.getInstance("HmacMD5");

            byte[] hmacKey = (encryptedEntry.getMd5()).getBytes();  //get key

            byte[] dataToHmac = (encryptedEntry.getData()).getBytes();

            SecretKeySpec signingKey = new SecretKeySpec(hmacKey, "HmacMD5");

            mac.init(signingKey);

            byte[] rawHmac = mac.doFinal(dataToHmac);

            encryptedEntry.setHmac(rawHmac);

            return rawHmac;
        }
        catch (Exception e)
        {
            e.printStackTrace();
        }
        return null;
    }
}

/**
 * Represents the client participating in the private set intersection shceme
 * The client hash a list of entries and wishes to learn the intersection of these entries
 * with the entries stored in a server as well as the data associated with each common entry
 * but without revealing to the server any entries outside the intersection
 */
class Client extends Participant
{
    static ArrayList<Entry> getEntries(String filename) throws IOException
    {
        BufferedReader br = null;

        try
        {
            ClassLoader classloader = Thread.currentThread().getContextClassLoader();

            InputStream is = classloader.getResourceAsStream(filename);

            br = new BufferedReader(new InputStreamReader(is));

            ArrayList<Entry> entries = new ArrayList<Entry>();

            String line;

            while ((line = br.readLine()) != null)
            {
                String name = getName(line);

                Entry entry = new Entry(name);

                entries.add(entry);
            }
            return entries;
        }
        catch (FileNotFoundException e)
        {
            System.out.println("File not found");
        }
        finally
        {
            br.close();
        }
        return null;
    }

    /**
     * Returns an arraylist with the entries included in the intersection of two sets
     * based on their SHA-1 fields
     * @param clientEntries
     * @param serverEntries
     * @return
     * @throws IOException
     */
    static ArrayList<Entry> checkForCommonEntries(ArrayList<Entry> clientEntries, ArrayList<Entry> serverEntries) throws IOException
    {
        try
        {
            ArrayList<Entry> commonEntries = new ArrayList<Entry>();

            for (Entry bobentry : clientEntries)
            {
                bobentry.setSha1(sha1Hash(bobentry.getName()));
            }

            for (Entry bobEntry : clientEntries)
            {
                for (Entry serverEntry : serverEntries)
                {
                    if (bobEntry.getSha1().equals(serverEntry.getSha1()))
                    {
                        commonEntries.add(serverEntry);
                    }
                }
            }
            return commonEntries;
        }
        catch (Exception e)
        {
            e.printStackTrace();
        }
        return null;
    }

    /**
     * Decrypts the associated data of the input entry using AES-128 in CBC mode
     * and the MD5 input parameter as the key
     * @param encryptedEntry
     * @param md5
     * @return
     */
    static byte[] decryptEntry(Entry encryptedEntry, String md5)
    {
        try
        {
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");

            String encryptedData = encryptedEntry.getData();

            IvParameterSpec iv = new IvParameterSpec(encryptedEntry.getIV());

            byte[] aesDecKey = (md5).getBytes("UTF-8"); //key

            byte[] aesDecInput = new Base64().decode(encryptedData.getBytes("UTF-8"));

            SecretKeySpec key = new SecretKeySpec(aesDecKey, "AES");

            cipher.init(Cipher.DECRYPT_MODE, key, iv);

            byte[] plaintext = cipher.doFinal(aesDecInput);

            return plaintext;

        }
        catch (NoSuchAlgorithmException e)
        {
            System.out.println("Invalid encryption algorithm");
        }
        catch (NoSuchPaddingException e)
        {
            System.out.println("Invalid padding selection");
        }
        catch (InvalidAlgorithmParameterException e)
        {
            System.out.println("Invalid algorithm parameters");
        }
        catch (InvalidKeyException e)
        {
            System.out.println("Invalid key");
        }
        catch (IllegalBlockSizeException e)
        {
            System.out.println("Illegal block size");
        }
        catch (BadPaddingException e)
        {
            System.out.println("Invalid padding specified");
        }
        catch (UnsupportedEncodingException e)
        {
            System.out.println("The encoding is not supported");
        }
        return null;
    }

    /**
     * Verifying the HMAC over the encrypted data of the input entry using the
     * md5 input parameter as the key
     * @param encryptedEntry
     * @param md5
     * @return
     */
    static boolean verifyMac(Entry encryptedEntry, String md5)
    {
        try
        {
            Mac mac = Mac.getInstance("HmacMD5");

            byte[] hmacKey = (md5).getBytes(); // get hmac key , bob's md5 output

            byte[] hmacInput = (encryptedEntry.getData().getBytes());

            SecretKeySpec key = new SecretKeySpec(hmacKey, "HmacMD5");

            mac.init(key);

            byte[] rawHmac = mac.doFinal(hmacInput);  //calculate hmac

            if (Arrays.equals(encryptedEntry.getHmac(), rawHmac))
            {
                return true;
            }
            else
            {
                return false;
            }
        }
        catch (NoSuchAlgorithmException e)
        {
            System.out.println("Invalid encryption algorithm");
        }
        catch (InvalidKeyException e)
        {
            System.out.println("Invalid key");
        }
        return false;
    }

    /**
     * Prints the entries included in the intersections of two sets and their associated data
     * @param matches
     * @param bobEntries
     */
    static protected void getCommonEntriesAndTheirData(ArrayList<Entry> matches, ArrayList<Entry> bobEntries)
    {
        for (Entry entry : bobEntries)
        {
            for (Entry encryptedEntry : matches)
            {
                if (Client.sha1Hash(entry.getName()).equals(encryptedEntry.getSha1()))
                {
                    if (Client.verifyMac(encryptedEntry, Client.md5Hash(entry.getName())))
                    {
                        System.out.println("HMAC successfully verified for " + entry.getName());

                        byte[] decryptedData = Client.decryptEntry(encryptedEntry, Client.md5Hash(entry.getName()));

                        System.out.println(entry.getName() + "'s associated data is: " + new String(decryptedData));
                    }
                }
            }
        }
    }

}




