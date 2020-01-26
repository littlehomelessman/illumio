//package illumio;

import java.io.*;
import java.util.*;

/**
 * @author Zhenke(Jeff) Xi
 * @email xizhenke@gmail.com
 * @linkedIn: https://www.linkedin.com/in/xzkjeff/
 */
public class FireWall {

    private List<String[]> rules = new ArrayList<>();
    private Map<String, List<Port>> outerMap = new HashMap<>();
    private Map<String, Map<Integer, Integer>> portBook = new HashMap<>();

    public static void main(String[] args){

        // MODIFY: Please use a valid absolute solution for testing
        String path = "/illumio/rules.csv";

        // Creating FireWall class
        FireWall fw = new FireWall(path);
        // Print out the rules in an organized way.
        fw.printRules();

        // Test Cases
        // API: acceptPacket(direction, protocol, port, IP_address)
        boolean res1 = fw.acceptPacket("inbound","tcp",80,"192.168.1.2");
        boolean res2 = fw.acceptPacket("inbound","udp",53,"192.168.2.1");
        boolean res3 = fw.acceptPacket("outbound", "tcp", 10234, "192.168.10.11");
        boolean res4 = fw.acceptPacket("inbound","tcp",81,"192.168.1.2");
        boolean res5 = fw.acceptPacket("inbound","udp",24,"52.12.48.92");
        boolean res6 = fw.acceptPacket("outbound","udp",24,"52.12.48.92");

        System.out.println("Sample test results:");
        System.out.printf("%-20s%-20s%-20s%-30s%-10s\n","direction:", "protocol:", "port:", "IP address:", "Allow?");
        System.out.printf("%-20s%-20s%-20s%-30s%-10s\n","inbound","tcp",80,"192.168.1.2", res1);
        System.out.printf("%-20s%-20s%-20s%-30s%-10s\n","inbound","udp",53,"192.168.2.1", res2);
        System.out.printf("%-20s%-20s%-20s%-30s%-10s\n","outbound", "tcp", 10234, "192.168.10.11", res3);
        System.out.printf("%-20s%-20s%-20s%-30s%-10s\n","inbound","tcp",81,"192.168.1.2", res4);
        System.out.printf("%-20s%-20s%-20s%-30s%-10s\n","inbound","udp",24,"52.12.48.92", res5);
        System.out.printf("%-20s%-20s%-20s%-30s%-10s\n","outbound","udp",1000,"52.12.48.92", res6);

    }


    /**
     * constructor: read rules from a csv file and build the mapping structure for query
     * @param pathToCsv file path
     */
    public FireWall(String pathToCsv){

        readFile(pathToCsv);

        // build the mapping structure
        buildMaps(rules, portBook);
    }

    /**
     * Read the rules in a csv file and store each line in a list of String-arrays
     * @param pathToCsv file path
     */
    private void readFile(String pathToCsv){

        Scanner fileIn = null ; // initializes fileIn to empty
        try
        {
            // Attempt to open the file
            fileIn = new Scanner( new FileInputStream(pathToCsv));
        }
        catch (FileNotFoundException e)
        {
            // If the file could not be found, this code is executed
            // and then the program exits
            System.out.println("File not found.");
            System.exit(0);
        }

        while(fileIn.hasNextLine()){
            String[] line = fileIn.nextLine().split(",");
            rules.add(line);
        }

        fileIn.close();
    }


    /**
     * print the read rules in an organized format
     */
    public void printRules(){

        System.out.printf("%-20s%-20s%-20s%-40s\n","direction:", "protocol:", "port:", "IP address:");
        for(String[] rule : this.rules){
            System.out.printf("%-20s%-20s%-20s%-40s\n",rule[0],rule[1],rule[2],rule[3]);
        }

    }


    /**
     * @param direction traffic direction
     * @param protocol traffic protocol
     * @param portNumber traffic port
     * @param addr traffic ip address
     * @return true if the traffic is allowed, otherwise, false.
     */
    public boolean acceptPacket(String direction, String protocol, int portNumber, String addr) {

        // Create the encoded key
        String key = direction + protocol;
        List<Port> pts = outerMap.get(key);

        // Find the index that locate the port that is smaller or equal to the current point
        // (Compare the 'start' if the port contains [start - end])
        // return -1 if such a port cannot be found
        int validPtNumber = validPort(pts, portNumber);

        if(validPtNumber != -1){
            Port pt = pts.get(validPtNumber);
            Ip targetIp = new Ip(addr);

            // Once the port is fond, perform binary search to locate the ip
            int lo = 0;
            int hi = pt.ips.size() - 1;

            while(lo <= hi){

                int mid = lo + (hi - lo) / 2;

                if(compareArr(pt.ips.get(mid).start, targetIp.start) == 0){

                    return true;

                }else if(pt.ips.get(mid).end != null && compareArr(pt.ips.get(mid).end, targetIp.start) < 0){

                    lo = mid + 1;

                }else if(pt.ips.get(mid).end != null
                        && compareArr(pt.ips.get(mid).start, targetIp.start) < 0
                        && compareArr(pt.ips.get(mid).end, targetIp.start) >= 0){

                    return true;

                }else if(compareArr(pt.ips.get(mid).start, targetIp.start) > 0){

                    hi = mid - 1;

                }else{

                    lo = mid + 1;
                }
            }
        }

        return false;
    }

    /**
     * @param pts List of ports of a direction + protocol combination
     * @param portNumber the port we will be testing
     * @return the index of the port that is the largest port among the ports smaller than portNumber, inclusively.
     */
    private int validPort(List<Port> pts, int portNumber){

        int lo = 0;
        int hi = pts.size() - 1;

        while(lo + 1 < hi){
            int mid = lo + (hi - lo) / 2;

            if( pts.get(mid).start == portNumber ){
                return mid;
            }else if(pts.get(mid).start < portNumber){
                lo = mid;
            }else{
                hi = mid;
            }
        }

        if(pts.get(hi).start <= portNumber){
            if( pts.get(hi).start == portNumber
                    || pts.get(hi).end != null && pts.get(hi).end >= portNumber){
                return hi;
            }
        }

        if(pts.get(lo).start <= portNumber){
            if(pts.get(lo).start == portNumber
                    ||pts.get(lo).end != null && pts.get(lo).end >= portNumber){
                return lo;
            }
        }

        return -1;
    }


    /**
     * Build the complete mapping structure for further query
     * @param rules read previously from a csv file, each row corresponds to a line in the csv file
     * @param portBook a map that associates the (direction + protocol) vs. the map of of port and its index in a port array
     */
    private void buildMaps(List<String[]> rules, Map<String, Map<Integer, Integer>> portBook){

        for(String[] rule: rules){

            String directionProtocol = rule[0] + rule[1];

            if(!outerMap.containsKey(directionProtocol)){
                outerMap.put(directionProtocol, new ArrayList<>());
            }

            List<Port> innerMap = outerMap.get(directionProtocol);

            if(!portBook.containsKey(directionProtocol)){
                portBook.put(directionProtocol, new HashMap<>());
            }

            addPort(rule[2], rule[3], innerMap, portBook.get(directionProtocol));
        }

        // Since now our outerMap have contained all rules we need.
        // We can sort the port list and ip list of each port to facilitate binary search to accelerate the verifying process
        for(Map.Entry<String, List<Port>> entry : outerMap.entrySet()){

            Collections.sort(entry.getValue(), (a, b) -> (Integer.compare(a.start, b.start)));

            for(Port pt : entry.getValue()){

                Collections.sort(pt.ips, (a, b) -> (compareIp(a, b)));

            }
        }
    }

    /**
     * helper function to add port to the mapping structure
     * @param port port number fetched from the rules
     * @param ip ip address fetched from the rules
     * @param innerMap list of Port under current direction + protocol combination
     * @param port2Idx a map that quickly determines if current port has shown before so we do not need to create it again
     */
    private void addPort(String port, String ip, List<Port> innerMap, Map<Integer, Integer> port2Idx){

        int bar = port.indexOf("-");
        // if we find '-' in our port string, we only fetch its first half as the 'start' attribute of the port object.
        int index = bar != -1? Integer.parseInt(port.substring(0, bar)) : Integer.parseInt(port);

        Integer idx = port2Idx.get(index);

        if(idx != null){
            innerMap.get(idx).ips.add(new Ip(ip));
        }else{

            Port newPt = new Port(port);
            newPt.ips.add(new Ip(ip));
            innerMap.add(newPt);

            port2Idx.put(newPt.start, innerMap.size() - 1);
        }

    }

    /**
     * Serve as a comparator for "Ip" instances
     * @param p1
     * @param p2
     * @return
     */
    private int compareIp(Ip p1, Ip p2){

        int[] a = p1.start;
        int[] b = p2.start;

        return compareArr(a, b);
    }

    /**
     * Compare two int arrays that represents an Ipv4 address
     * @param a
     * @param b
     * @return
     */
    private int compareArr(int[] a, int[] b){

        for(int i = 0; i < a.length; i ++){

            int temp = Integer.compare(a[i], b[i]);
            if(temp == 0){
                continue;
            }
            return temp;
        }
        return 0;
    }


    /**
     * Port number storing the associated range of ip numbers and port range if available
     */
    class Port{

        Integer start;
        Integer end;
        List<Ip> ips = new ArrayList<>();

        public Port(String port){

            int bar = port.indexOf('-');

            if(bar == -1){
                this.start = Integer.parseInt(port);

            }else{

                this.start = Integer.parseInt(port.substring(0, bar));
                this.end = Integer.parseInt(port.substring(bar + 1));
            }
        }
    }


    /**
     * Store the ip address and its associated range
     * Each ip address are store as an int array
     * For example '192.168.2.1' ==> [192, 168, 2, 1]
     */
    class Ip{

        int[] start;
        int[] end;

        public Ip(String ip){

            int bar = ip.indexOf('-');

            if(bar == -1){
                start = new int[4];
                String[] temp = ip.split("\\.");

                for(int i = 0; i < start.length; i ++){
                    start[i] = Integer.parseInt(temp[i]);
                }

            }else{
                start = new int[4];
                end = new int[4];

                String[] temp1 = ip.substring(0, bar).split("\\.");
                String[] temp2 = ip.substring(bar + 1).split("\\.");

                for(int i = 0; i < start.length; i ++){
                    start[i] = Integer.parseInt(temp1[i]);
                    end[i] = Integer.parseInt(temp2[i]);
                }
            }
        }
    }
}
