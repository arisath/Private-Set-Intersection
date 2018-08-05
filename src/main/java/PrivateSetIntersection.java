import java.lang.reflect.Field;
import java.util.ArrayList;

public class PrivateSetIntersection
{
    public static void main(String[] args) throws Exception
    {
        try
        {
            ArrayList<Entry> serverEntries = Server.getEntries("server.txt");

            ArrayList<Entry> clientEntries = Client.getEntries("client.txt");

            ArrayList<Entry> serverEncryptedEntries = new ArrayList<Entry>();

            for (Entry e : serverEntries)
            {
               serverEncryptedEntries.add(Server.encryptAndHmac(e));

            }

           ArrayList<Entry> matches= Client.checkForCommonEntries(clientEntries,serverEncryptedEntries);

           Client.getCommonEntriesAndTheirData(matches,clientEntries);


        }
        catch (Exception e)
        {
            e.printStackTrace();
        }
    }

}
