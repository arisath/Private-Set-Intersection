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


public class Participant
{
    static String getName(String line) throws IOException
    {
        String[] entry = line.split(" ");

        String name = (entry[0]);

        return name;
    }

    static String getAssociatedData(String line) throws IOException
    {
        String[] entry = line.split(" ");

        String associatedData = entry[1];

        return associatedData;
    }

    static String sha1Hash(String input)
    {
        String digest = DigestUtils.sha1Hex(input);

        return digest;
    }

    static String md5Hash(String input)
    {
        String digest = DigestUtils.md5Hex(input);

        return digest;

    }

}

class Server extends Participant
{
    static ArrayList<Entry> getEntries(String filename) throws IOException
    {
        FileReader fileReader;

        BufferedReader br = null;

        try
        {
            fileReader = new FileReader(new File(filename));

            br = new BufferedReader(fileReader);

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

    static Entry encryptAesCbc(Entry entry)
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

            byte[] hmac = computeHMac(entry);

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

    static byte[] computeHMac(Entry encryptedEntry)
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

class Client extends Participant
{
    static ArrayList<Entry> getEntries(String filename) throws IOException
    {
        FileReader fileReader;

        BufferedReader br = null;

        try
        {
            fileReader = new FileReader(new File(filename));

            br = new BufferedReader(fileReader);

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
            } else
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

    static protected void printCommonEntriesData(ArrayList<Entry> matches, ArrayList<Entry> bobEntries)
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




