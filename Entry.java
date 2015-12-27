/**
 * Class representing an entry stored in either a client or a server
 * A client entry includes a name while a server entry includes a name
 * as well as some associated data with it
 */
public class Entry
{
    private String name;

    private String md5;

    private String sha1;

    private byte[] IV;

    private String data;

    private byte[] hmac;

    /**
     * Initialises a new Entry object and sets the name field
     * @param name
     */
    Entry(String name)
    {
        this.name=name;
    }

    /**
     * Initialises a new Entry object and sets the
     * md5, sha1 and data fields
     * @param md5
     * @param sha1
     * @param data
     */
    Entry(String md5, String sha1, String data)
    {
        this.md5=md5;

        this.sha1=sha1;

        this.data = data;
    }

    /**
     * Returns the name of the Entry
     * @return
     */
    public String getName()
    {
        return name;
    }

    /**
     * Sets the name of the Entry
     * @param name
     */
    public void setName(String name)
    {
        this.name = name;
    }

    /**
     * Returns the md5 field of the Entry
     * @return
     */
    protected String getMd5()
    {
        return md5;
    }

    /**
     * Sets the md5 field of the Entry
     * @param md5
     */
    protected void setMd5(String md5)
    {
        this.md5 = md5;
    }

    /**
     * Returns the sha1 field of the Entry
     * @return
     */
    protected String getSha1()
    {
        return sha1;
    }
    
    /**
     * Sets the sha1 field of the Entry
     * @return
     */
    protected void setSha1(String sha1)
    {
        this.sha1 = sha1;
    }

    /**
     * Returns a byte array with the the IV field of the Entry
     * @return
     */
    protected byte[] getIV()
    {
        return IV;
    }

    /**
     * Sets the IV field of the Entry
     * @param IV
     */
    protected void setIV(byte[] IV)
    {
        this.IV = IV;
    }

    /**
     * Returns the data associated with this Entry
     * @return
     */
    public String getData()
    {
        return data;
    }

    /**
     * Sets the data field of this Entry
     * @param data
     */
    protected void setData(String data)
    {
        this.data = data;
    }

    /**
     * Returns a byte array with the hmac of this Entry
     * @return
     */
    protected byte[] getHmac()
    {
        return hmac;
    }

    /**
     * Sets the hmac field of this Entry
     * @param hmac
     */
    protected void setHmac(byte[] hmac)
    {
        this.hmac = hmac;
    }

}
