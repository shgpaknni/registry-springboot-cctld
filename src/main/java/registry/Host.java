package registry;

import java.util.ArrayList;
import java.util.List;

public class Host {

    public enum Status {
        OK,
        CLIENT_DELETE_PROHIBITED,
        CLIENT_UPDATE_PROHIBITED,
        SERVER_DELETE_PROHIBITED,
        SERVER_UPDATE_PROHIBITED
    }

    private final String name;
    private final String registrarId;
    private final List<String> ipv4;
    private final List<String> ipv6;
    private final List<Status> statuses;

    public Host(
            String name,
            String registrarId,
            List<String> ipv4,
            List<String> ipv6
    ) {
        this.name = name;
        this.registrarId = registrarId;
        this.ipv4 = new ArrayList<>(ipv4);
        this.ipv6 = new ArrayList<>(ipv6);
        this.statuses = new ArrayList<>();
        this.statuses.add(Status.OK);
    }

    public String getName() {
        return name;
    }

    public String getRegistrarId() {
        return registrarId;
    }

    public List<String> getIpv4() {
        return List.copyOf(ipv4);
    }

    public List<String> getIpv6() {
        return List.copyOf(ipv6);
    }

    public List<Status> getStatuses() {
        return List.copyOf(statuses);
    }

    public void addIpv4(String address) {
        if (!ipv4.contains(address)) {
            ipv4.add(address);
        }
    }

    public void addIpv6(String address) {
        if (!ipv6.contains(address)) {
            ipv6.add(address);
        }
    }

    public void removeIpv4(String address) {
        ipv4.remove(address);
    }

    public void removeIpv6(String address) {
        ipv6.remove(address);
    }

    public void addStatus(Status status) {
        if (!statuses.contains(status)) {
            statuses.add(status);
        }
    }

    public void removeStatus(Status status) {
        if (status != Status.OK) {
            statuses.remove(status);
        }
    }
}