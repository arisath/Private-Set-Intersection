public class Entry
{
    private String name;

    private String md5;

    private String sha1;

    private byte[] IV;

    private String data;

    private byte[] hmac;

    Entry(String name)
    {
        this.name=name;
    }

    Entry(String md5, String sha1, String data)
    {
        this.md5=md5;

        this.sha1=sha1;

        this.data = data;
    }

    Entry(String md5, String sha1, byte[] IV, String data)
    {
        this.md5 = md5;

        this.sha1 = sha1;

        this.IV = IV;

        this.data = data;
    }

    public String getName()
    {
        return name;
    }

    public void setName(String name)
    {
        this.name = name;
    }

    protected String getMd5()
    {
        return md5;
    }

    protected void setMd5(String md5)
    {
        this.md5 = md5;
    }

    protected String getSha1()
    {
        return sha1;
    }

    protected void setSha1(String sha1)
    {
        this.sha1 = sha1;
    }

    protected byte[] getIV()
    {
        return IV;
    }

    protected void setIV(byte[] IV)
    {
        this.IV = IV;
    }

    public String getData()
    {
        return data;
    }

    protected void setData(String data)
    {
        this.data = data;
    }

    protected byte[] getHmac()
    {
        return hmac;
    }

    protected void setHmac(byte[] hmac)
    {
        this.hmac = hmac;
    }
}
