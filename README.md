<img src="https://github.com/Bareflank/extended_apis/raw/master/doc/images/bareflank_extended_apis_logo.jpg" width="501">

## Description

The [Bareflank Hypervisor](https://github.com/Bareflank/hypervisor)'s main 
goal is to provide the "bare" minimum hypervisor. Since Bareflank supports 
C++ 11/14, multiple operating systems, and a full toolstack, it's not as 
simple as say [SimpleVisor](https://github.com/ionescu007/SimpleVisor),
but still adheres to the same basic principles of leaving out the complexity 
of a full blown hypervisor in favor of an implementation that is simple to 
read and follow. 

It is our goal to provide a hypervisor that others can extend to create 
their own hypervisors. To this end, it is likely that when creating your
own hypervisor, some tasks will be redundant. For example, Windows 
makes a lot of MSR accesses. When running Bareflank this is obvious as
Windows takes a significant performance penalty with running Bareflank 
since all MSR accesses are emulated. The first step most people will take 
on an Intel platform is to enable VPID and MSR bitmaps to increase 
performance. The process of setting up these resources is the same, 
regardless of what type of hypervisor you might be creating. 

The purpose of this repository, is to provide an extended set of APIs to 
build your hypervisors from. Some of these APIs include:

- MSR / IO Bitmaps
- Extended Page Tables (EPT)
- Event Injection
- Guest Support
- [LibVMI](https://github.com/libvmi/libvmi) Support

## Links

[Bareflank Hypervisor Website](http://bareflank.github.io/hypervisor/) <br>
[Bareflank Hypervisor API Documentation](http://bareflank.github.io/hypervisor/html/)

## Roadmap

### Version 1.2

Target: Janurary 2017

- VPID
- CPUID Emulation
- MSR Bitmaps
- IO Bitmaps
- Extended Page Tables (EPT)
- Guest Support
- [LibVMI](https://github.com/libvmi/libvmi) Support

### Version 1.3

Target: June 2017

- Event Injection
- Guest to Hypervisor
- Nest Virtualization
- Control Register Emulation
- Trap Flag Monitoring

## Contributing

We are always looking for feedback, feature requests, bug reports, and
help with writing the code itself. If you would like to participate in
this project, the following Wiki page provides more information on how
to do so:

https://github.com/Bareflank/hypervisor/wiki/Contributing

## License

The Bareflank Hypervisor is licensed under the GNU Lesser General Public License
v2.1 (LGPL).

