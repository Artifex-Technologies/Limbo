package virt

import (
	"encoding/xml"
	"fmt"

	"github.com/Artifex-Technologies/Limbo/internal/manifest"
)

// attrs is a catch-all element whose only content is attributes; omitempty
// keeps each use to the attributes it sets.
type attrs struct {
	Type    string `xml:"type,attr,omitempty"`
	Mode    string `xml:"mode,attr,omitempty"`
	Name    string `xml:"name,attr,omitempty"`
	Dev     string `xml:"dev,attr,omitempty"`
	Bus     string `xml:"bus,attr,omitempty"`
	File    string `xml:"file,attr,omitempty"`
	Dir     string `xml:"dir,attr,omitempty"`
	Network string `xml:"network,attr,omitempty"`
	Address string `xml:"address,attr,omitempty"`
	Model   string `xml:"model,attr,omitempty"`
	State   string `xml:"state,attr,omitempty"`
	Path    string `xml:"path,attr,omitempty"`
}

type memory struct {
	Unit  string `xml:"unit,attr"`
	Value int    `xml:",chardata"`
}

type memoryBacking struct {
	Source attrs `xml:"source"`
	Access attrs `xml:"access"`
}

type hyperV struct {
	Relaxed   attrs `xml:"relaxed"`
	Spinlocks struct {
		State   string `xml:"state,attr"`
		Retries int    `xml:"retries,attr"`
	} `xml:"spinlocks"`
}

type domain struct {
	XMLName       xml.Name       `xml:"domain"`
	Type          string         `xml:"type,attr"`
	Name          string         `xml:"name"`
	Memory        memory         `xml:"memory"`
	VCPU          int            `xml:"vcpu"`
	MemoryBacking *memoryBacking `xml:"memoryBacking"`
	OS            struct {
		Type struct {
			Arch    string `xml:"arch,attr"`
			Machine string `xml:"machine,attr"`
			Value   string `xml:",chardata"`
		} `xml:"type"`
	} `xml:"os"`
	Features struct {
		ACPI   struct{} `xml:"acpi"`
		APIC   struct{} `xml:"apic"`
		HyperV *hyperV  `xml:"hyperv"`
	} `xml:"features"`
	CPU        attrs   `xml:"cpu"`
	OnPoweroff string  `xml:"on_poweroff"`
	OnReboot   string  `xml:"on_reboot"`
	OnCrash    string  `xml:"on_crash"`
	Devices    devices `xml:"devices"`
}

type devices struct {
	Disk       []disk      `xml:"disk"`
	Interface  iface       `xml:"interface"`
	Filesystem *filesystem `xml:"filesystem"`
	Serial     *serial     `xml:"serial"`
	Channel    channel     `xml:"channel"`
	Video      struct {
		Model attrs `xml:"model"`
	} `xml:"video"`
	MemBalloon attrs     `xml:"memballoon"`
	Hostdev    []hostdev `xml:"hostdev"`
}

// hostdev is a whole host PCI device given to the guest through VFIO (managed=yes
// has libvirt unbind it from its host driver at start and rebind it at teardown),
// or a single host USB device named by vendor and product (QEMU claims it through
// usbfs for the guest's lifetime; managed is not used for USB).
type hostdev struct {
	Mode    string `xml:"mode,attr"`
	Type    string `xml:"type,attr"`
	Managed string `xml:"managed,attr,omitempty"`
	Source  struct {
		Address *pciAddress `xml:"address"`
		Vendor  *usbID      `xml:"vendor"`
		Product *usbID      `xml:"product"`
	} `xml:"source"`
}

type pciAddress struct {
	Domain   string `xml:"domain,attr"`
	Bus      string `xml:"bus,attr"`
	Slot     string `xml:"slot,attr"`
	Function string `xml:"function,attr"`
}

type usbID struct {
	ID string `xml:"id,attr"`
}

// usbHostdev turns "5059:4040" into a hostdev. The ID was validated by the manifest; it is re-checked and re-split here
// rather than spliced into the XML as one string.
func usbHostdev(id string) (hostdev, error) {
	var h hostdev
	if !manifest.USBRe.MatchString(id) {
		return h, fmt.Errorf("virt: bad USB ID %q", id)
	}
	h.Mode, h.Type = "subsystem", "usb"
	h.Source.Vendor, h.Source.Product = &usbID{ID: "0x" + id[0:4]}, &usbID{ID: "0x" + id[5:9]}
	return h, nil
}

// pciHostdev turns "0000:03:00.0" into a hostdev. The address was validated by the
// manifest; it is re-split here rather than spliced into the XML as one string.
func pciHostdev(addr string) (hostdev, error) {
	var h hostdev
	var dom, bus, slot, fn string
	if len(addr) != 12 || addr[4] != ':' || addr[7] != ':' || addr[10] != '.' {
		return h, fmt.Errorf("virt: bad PCI address %q", addr)
	}
	dom, bus, slot, fn = addr[0:4], addr[5:7], addr[8:10], addr[11:12]
	h.Mode, h.Type, h.Managed = "subsystem", "pci", "yes"
	h.Source.Address = &pciAddress{Domain: "0x" + dom, Bus: "0x" + bus, Slot: "0x" + slot, Function: "0x" + fn}
	return h, nil
}

type disk struct {
	Type     string    `xml:"type,attr"`
	Device   string    `xml:"device,attr"`
	Driver   attrs     `xml:"driver"`
	Source   attrs     `xml:"source"`
	Target   attrs     `xml:"target"`
	Boot     *bootAt   `xml:"boot"`
	ReadOnly *struct{} `xml:"readonly"`
}

// bootAt is a device's place in the boot order.
type bootAt struct {
	Order int `xml:"order,attr"`
}

type iface struct {
	Type   string `xml:"type,attr"`
	MAC    attrs  `xml:"mac"`
	Source attrs  `xml:"source"`
	Target attrs  `xml:"target"`
	Model  attrs  `xml:"model"`
}

type filesystem struct {
	Type       string    `xml:"type,attr"`
	AccessMode string    `xml:"accessmode,attr"`
	Driver     attrs     `xml:"driver"`
	Source     attrs     `xml:"source"`
	Target     attrs     `xml:"target"`
	ReadOnly   *struct{} `xml:"readonly,omitempty"`
}

// serial is a file-backed serial port: the guest's console output is appended to
// a host file, and nothing can be typed into it.
type serial struct {
	Type   string `xml:"type,attr"`
	Source attrs  `xml:"source"`
	Target struct {
		Port int `xml:"port,attr"`
	} `xml:"target"`
}

type channel struct {
	Type   string `xml:"type,attr"`
	Target attrs  `xml:"target"`
}

// OverlayName is the file name of a disposable guest's per-guest overlay inside
// the state directory.
func OverlayName(m *manifest.Manifest) string { return m.Name + ".overlay.qcow2" }

// PersistentDiskName is the file name of a persistent guest's own disk inside the state directory: an overlay backed
// by the base image, kept across Down, so the base image is never written and several guests can share it.
func PersistentDiskName(m *manifest.Manifest) string { return m.Name + ".disk.qcow2" }

// DiskName is the disk a guest boots from (inside the state directory): its throwaway overlay if it is disposable,
// its own kept overlay otherwise.
func DiskName(m *manifest.Manifest) string {
	if m.Disposable {
		return OverlayName(m)
	}
	return PersistentDiskName(m)
}

// DomainXML returns the libvirt domain definition. rootDisk is the disk the
// guest boots from: always an overlay in the state directory (see DiskName),
// never the base image itself.
//
// What is deliberately absent matters as much as what is present: no graphics
// device, no USB redirection, no sound, no SPICE agent, no shared folder unless
// the manifest names an exchange directory. The clipboard is therefore only
// ever reachable through the display protocol (RDP/waypipe), where the launcher
// controls it. Windows output is UNVERIFIED — see package license.
func DomainXML(m *manifest.Manifest, rootDisk string) ([]byte, error) {
	d := domain{Type: "kvm", Name: DomainName(m), VCPU: m.CPUs}
	d.Memory = memory{Unit: "MiB", Value: m.MemoryMB}
	d.OS.Type.Arch, d.OS.Type.Machine, d.OS.Type.Value = "x86_64", "q35", "hvm"
	d.CPU = attrs{Mode: "host-passthrough"}
	d.OnPoweroff, d.OnReboot, d.OnCrash = "destroy", "restart", "destroy"

	// Disk names follow the bus: libvirt places a SATA disk by its sdX letter, so a SATA disk named vda would take the
	// first CD's place (seen the first time a Windows guest was defined, 2026-11-08).
	bus, nic := "virtio", "virtio"
	rootDev, seedDev := "vda", "sda"
	if m.OS == manifest.OSWindows {
		rootDev, seedDev = "sda", "sdb"
		// A stock Windows install has no virtio drivers; sata/e1000e boot
		// everywhere. Switch once a driver ISO is part of the flow.
		bus, nic = "sata", "e1000e"
		d.Features.HyperV = &hyperV{Relaxed: attrs{State: "on"}}
		d.Features.HyperV.Spinlocks.State, d.Features.HyperV.Spinlocks.Retries = "on", 8191
	}

	root := disk{
		Type: "file", Device: "disk",
		Driver: attrs{Name: "qemu", Type: "qcow2"},
		Source: attrs{File: rootDisk},
		Target: attrs{Dev: rootDev, Bus: bus},
	}
	if m.OS == manifest.OSWindows && m.Windows.ISO != "" {
		// The disk first; an empty disk falls through to the installation CD by name (a per-device order: the
		// firmware tries only the first CD drive for a plain "cdrom", and that is the seed CD).
		root.Boot = &bootAt{Order: 1}
	}
	d.Devices.Disk = []disk{root}
	if m.Provision.SeedISO != "" {
		d.Devices.Disk = append(d.Devices.Disk, disk{
			Type: "file", Device: "cdrom",
			Driver:   attrs{Name: "qemu", Type: "raw"},
			Source:   attrs{File: m.Provision.SeedISO},
			Target:   attrs{Dev: seedDev, Bus: "sata"},
			ReadOnly: &struct{}{},
		})
	}

	if m.OS == manifest.OSWindows && m.Windows.ISO != "" {
		d.Devices.Disk = append(d.Devices.Disk, disk{
			Type: "file", Device: "cdrom",
			Driver:   attrs{Name: "qemu", Type: "raw"},
			Source:   attrs{File: m.Windows.ISO},
			Target:   attrs{Dev: "sdc", Bus: "sata"},
			Boot:     &bootAt{Order: 2},
			ReadOnly: &struct{}{},
		})
	}

	d.Devices.Interface = iface{
		Type:   "network",
		MAC:    attrs{Address: Addr(m).MAC},
		Source: attrs{Network: NetworkName(m)},
		Target: attrs{Dev: TapName(m)},
		Model:  attrs{Type: nic},
	}
	d.Devices.Channel = channel{Type: "unix", Target: attrs{Type: "virtio", Name: "org.qemu.guest_agent.0"}}
	// Headless: the application is shown over waypipe/RDP, not a console, so no
	// display adapter is attached (and no virtio-gpu device model is required).
	// Windows gets a plain VGA adapter with no display attached to it (no VNC or
	// SPICE): its installer and boot screens expect one, and `limbo screenshot`
	// reads it to see an installation's progress.
	d.Devices.Video.Model = attrs{Type: "none"}
	if m.OS == manifest.OSWindows {
		d.Devices.Video.Model = attrs{Type: "vga"}
	}
	d.Devices.MemBalloon = attrs{Model: "none"}

	for _, a := range m.Devices.PCI {
		h, err := pciHostdev(a)
		if err != nil {
			return nil, err
		}
		d.Devices.Hostdev = append(d.Devices.Hostdev, h)
	}
	for _, id := range m.Devices.USB {
		h, err := usbHostdev(id)
		if err != nil {
			return nil, err
		}
		d.Devices.Hostdev = append(d.Devices.Hostdev, h)
	}
	if m.ConsoleLog != "" {
		d.Devices.Serial = &serial{Type: "file", Source: attrs{Path: m.ConsoleLog}}
	}
	if m.ExchangeDir != "" {
		d.MemoryBacking = &memoryBacking{Source: attrs{Type: "memfd"}, Access: attrs{Mode: "shared"}}
		d.Devices.Filesystem = &filesystem{
			Type: "mount", AccessMode: "passthrough",
			Driver: attrs{Type: "virtiofs"},
			Source: attrs{Dir: m.ExchangeDir},
			Target: attrs{Dir: "limbo-exchange"},
		}
		if !m.ExchangeWritable {
			d.Devices.Filesystem.ReadOnly = &struct{}{} // read-only on the host's side (virtiofsd --readonly)
		}
	}
	return marshal(d)
}

type network struct {
	XMLName xml.Name `xml:"network"`
	Name    string   `xml:"name"`
	Forward *attrs   `xml:"forward"`
	Bridge  attrs    `xml:"bridge"`
	IP      struct {
		Address string `xml:"address,attr"`
		Netmask string `xml:"netmask,attr"`
		DHCP    struct {
			Host struct {
				MAC  string `xml:"mac,attr"`
				Name string `xml:"name,attr"`
				IP   string `xml:"ip,attr"`
			} `xml:"host"`
		} `xml:"dhcp"`
	} `xml:"ip"`
}

// NetworkXML returns the guest's private libvirt network. Mode "none" gets an
// isolated network (no <forward>), so even if the firewall rules failed to load
// the guest has no route out; the other modes NAT, and package policy narrows
// what NAT may reach.
func NetworkXML(m *manifest.Manifest) ([]byte, error) {
	a := Addr(m)
	n := network{Name: NetworkName(m)}
	if m.Network.Mode != manifest.NetNone {
		n.Forward = &attrs{Mode: "nat"}
	}
	n.Bridge = attrs{Name: BridgeName(m)}
	n.IP.Address, n.IP.Netmask = a.Gateway.String(), "255.255.255.0"
	n.IP.DHCP.Host.MAC, n.IP.DHCP.Host.Name, n.IP.DHCP.Host.IP = a.MAC, m.Name, a.Guest.String()
	return marshal(n)
}

func marshal(v any) ([]byte, error) {
	b, err := xml.MarshalIndent(v, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("virt: %w", err)
	}
	return append(b, '\n'), nil
}
