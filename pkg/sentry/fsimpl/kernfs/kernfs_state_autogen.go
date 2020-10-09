// automatically generated by stateify.

package kernfs

import (
	"gvisor.dev/gvisor/pkg/state"
)

func (d *DentryRefs) StateTypeName() string {
	return "pkg/sentry/fsimpl/kernfs.DentryRefs"
}

func (d *DentryRefs) StateFields() []string {
	return []string{
		"refCount",
	}
}

func (d *DentryRefs) beforeSave() {}

func (d *DentryRefs) StateSave(stateSinkObject state.Sink) {
	d.beforeSave()
	stateSinkObject.Save(0, &d.refCount)
}

func (d *DentryRefs) afterLoad() {}

func (d *DentryRefs) StateLoad(stateSourceObject state.Source) {
	stateSourceObject.Load(0, &d.refCount)
}

func (d *DynamicBytesFile) StateTypeName() string {
	return "pkg/sentry/fsimpl/kernfs.DynamicBytesFile"
}

func (d *DynamicBytesFile) StateFields() []string {
	return []string{
		"InodeAttrs",
		"InodeNoStatFS",
		"InodeNoopRefCount",
		"InodeNotDirectory",
		"InodeNotSymlink",
		"locks",
		"data",
	}
}

func (d *DynamicBytesFile) beforeSave() {}

func (d *DynamicBytesFile) StateSave(stateSinkObject state.Sink) {
	d.beforeSave()
	stateSinkObject.Save(0, &d.InodeAttrs)
	stateSinkObject.Save(1, &d.InodeNoStatFS)
	stateSinkObject.Save(2, &d.InodeNoopRefCount)
	stateSinkObject.Save(3, &d.InodeNotDirectory)
	stateSinkObject.Save(4, &d.InodeNotSymlink)
	stateSinkObject.Save(5, &d.locks)
	stateSinkObject.Save(6, &d.data)
}

func (d *DynamicBytesFile) afterLoad() {}

func (d *DynamicBytesFile) StateLoad(stateSourceObject state.Source) {
	stateSourceObject.Load(0, &d.InodeAttrs)
	stateSourceObject.Load(1, &d.InodeNoStatFS)
	stateSourceObject.Load(2, &d.InodeNoopRefCount)
	stateSourceObject.Load(3, &d.InodeNotDirectory)
	stateSourceObject.Load(4, &d.InodeNotSymlink)
	stateSourceObject.Load(5, &d.locks)
	stateSourceObject.Load(6, &d.data)
}

func (d *DynamicBytesFD) StateTypeName() string {
	return "pkg/sentry/fsimpl/kernfs.DynamicBytesFD"
}

func (d *DynamicBytesFD) StateFields() []string {
	return []string{
		"FileDescriptionDefaultImpl",
		"DynamicBytesFileDescriptionImpl",
		"LockFD",
		"vfsfd",
		"inode",
	}
}

func (d *DynamicBytesFD) beforeSave() {}

func (d *DynamicBytesFD) StateSave(stateSinkObject state.Sink) {
	d.beforeSave()
	stateSinkObject.Save(0, &d.FileDescriptionDefaultImpl)
	stateSinkObject.Save(1, &d.DynamicBytesFileDescriptionImpl)
	stateSinkObject.Save(2, &d.LockFD)
	stateSinkObject.Save(3, &d.vfsfd)
	stateSinkObject.Save(4, &d.inode)
}

func (d *DynamicBytesFD) afterLoad() {}

func (d *DynamicBytesFD) StateLoad(stateSourceObject state.Source) {
	stateSourceObject.Load(0, &d.FileDescriptionDefaultImpl)
	stateSourceObject.Load(1, &d.DynamicBytesFileDescriptionImpl)
	stateSourceObject.Load(2, &d.LockFD)
	stateSourceObject.Load(3, &d.vfsfd)
	stateSourceObject.Load(4, &d.inode)
}

func (s *SeekEndConfig) StateTypeName() string {
	return "pkg/sentry/fsimpl/kernfs.SeekEndConfig"
}

func (s *SeekEndConfig) StateFields() []string {
	return nil
}

func (g *GenericDirectoryFDOptions) StateTypeName() string {
	return "pkg/sentry/fsimpl/kernfs.GenericDirectoryFDOptions"
}

func (g *GenericDirectoryFDOptions) StateFields() []string {
	return []string{
		"SeekEnd",
	}
}

func (g *GenericDirectoryFDOptions) beforeSave() {}

func (g *GenericDirectoryFDOptions) StateSave(stateSinkObject state.Sink) {
	g.beforeSave()
	stateSinkObject.Save(0, &g.SeekEnd)
}

func (g *GenericDirectoryFDOptions) afterLoad() {}

func (g *GenericDirectoryFDOptions) StateLoad(stateSourceObject state.Source) {
	stateSourceObject.Load(0, &g.SeekEnd)
}

func (g *GenericDirectoryFD) StateTypeName() string {
	return "pkg/sentry/fsimpl/kernfs.GenericDirectoryFD"
}

func (g *GenericDirectoryFD) StateFields() []string {
	return []string{
		"FileDescriptionDefaultImpl",
		"DirectoryFileDescriptionDefaultImpl",
		"LockFD",
		"seekEnd",
		"vfsfd",
		"children",
		"off",
	}
}

func (g *GenericDirectoryFD) beforeSave() {}

func (g *GenericDirectoryFD) StateSave(stateSinkObject state.Sink) {
	g.beforeSave()
	stateSinkObject.Save(0, &g.FileDescriptionDefaultImpl)
	stateSinkObject.Save(1, &g.DirectoryFileDescriptionDefaultImpl)
	stateSinkObject.Save(2, &g.LockFD)
	stateSinkObject.Save(3, &g.seekEnd)
	stateSinkObject.Save(4, &g.vfsfd)
	stateSinkObject.Save(5, &g.children)
	stateSinkObject.Save(6, &g.off)
}

func (g *GenericDirectoryFD) afterLoad() {}

func (g *GenericDirectoryFD) StateLoad(stateSourceObject state.Source) {
	stateSourceObject.Load(0, &g.FileDescriptionDefaultImpl)
	stateSourceObject.Load(1, &g.DirectoryFileDescriptionDefaultImpl)
	stateSourceObject.Load(2, &g.LockFD)
	stateSourceObject.Load(3, &g.seekEnd)
	stateSourceObject.Load(4, &g.vfsfd)
	stateSourceObject.Load(5, &g.children)
	stateSourceObject.Load(6, &g.off)
}

func (i *InodeNoopRefCount) StateTypeName() string {
	return "pkg/sentry/fsimpl/kernfs.InodeNoopRefCount"
}

func (i *InodeNoopRefCount) StateFields() []string {
	return []string{}
}

func (i *InodeNoopRefCount) beforeSave() {}

func (i *InodeNoopRefCount) StateSave(stateSinkObject state.Sink) {
	i.beforeSave()
}

func (i *InodeNoopRefCount) afterLoad() {}

func (i *InodeNoopRefCount) StateLoad(stateSourceObject state.Source) {
}

func (i *InodeDirectoryNoNewChildren) StateTypeName() string {
	return "pkg/sentry/fsimpl/kernfs.InodeDirectoryNoNewChildren"
}

func (i *InodeDirectoryNoNewChildren) StateFields() []string {
	return []string{}
}

func (i *InodeDirectoryNoNewChildren) beforeSave() {}

func (i *InodeDirectoryNoNewChildren) StateSave(stateSinkObject state.Sink) {
	i.beforeSave()
}

func (i *InodeDirectoryNoNewChildren) afterLoad() {}

func (i *InodeDirectoryNoNewChildren) StateLoad(stateSourceObject state.Source) {
}

func (i *InodeNotDirectory) StateTypeName() string {
	return "pkg/sentry/fsimpl/kernfs.InodeNotDirectory"
}

func (i *InodeNotDirectory) StateFields() []string {
	return []string{}
}

func (i *InodeNotDirectory) beforeSave() {}

func (i *InodeNotDirectory) StateSave(stateSinkObject state.Sink) {
	i.beforeSave()
}

func (i *InodeNotDirectory) afterLoad() {}

func (i *InodeNotDirectory) StateLoad(stateSourceObject state.Source) {
}

func (i *InodeNoDynamicLookup) StateTypeName() string {
	return "pkg/sentry/fsimpl/kernfs.InodeNoDynamicLookup"
}

func (i *InodeNoDynamicLookup) StateFields() []string {
	return []string{}
}

func (i *InodeNoDynamicLookup) beforeSave() {}

func (i *InodeNoDynamicLookup) StateSave(stateSinkObject state.Sink) {
	i.beforeSave()
}

func (i *InodeNoDynamicLookup) afterLoad() {}

func (i *InodeNoDynamicLookup) StateLoad(stateSourceObject state.Source) {
}

func (i *InodeNotSymlink) StateTypeName() string {
	return "pkg/sentry/fsimpl/kernfs.InodeNotSymlink"
}

func (i *InodeNotSymlink) StateFields() []string {
	return []string{}
}

func (i *InodeNotSymlink) beforeSave() {}

func (i *InodeNotSymlink) StateSave(stateSinkObject state.Sink) {
	i.beforeSave()
}

func (i *InodeNotSymlink) afterLoad() {}

func (i *InodeNotSymlink) StateLoad(stateSourceObject state.Source) {
}

func (i *InodeAttrs) StateTypeName() string {
	return "pkg/sentry/fsimpl/kernfs.InodeAttrs"
}

func (i *InodeAttrs) StateFields() []string {
	return []string{
		"devMajor",
		"devMinor",
		"ino",
		"mode",
		"uid",
		"gid",
		"nlink",
	}
}

func (i *InodeAttrs) beforeSave() {}

func (i *InodeAttrs) StateSave(stateSinkObject state.Sink) {
	i.beforeSave()
	stateSinkObject.Save(0, &i.devMajor)
	stateSinkObject.Save(1, &i.devMinor)
	stateSinkObject.Save(2, &i.ino)
	stateSinkObject.Save(3, &i.mode)
	stateSinkObject.Save(4, &i.uid)
	stateSinkObject.Save(5, &i.gid)
	stateSinkObject.Save(6, &i.nlink)
}

func (i *InodeAttrs) afterLoad() {}

func (i *InodeAttrs) StateLoad(stateSourceObject state.Source) {
	stateSourceObject.Load(0, &i.devMajor)
	stateSourceObject.Load(1, &i.devMinor)
	stateSourceObject.Load(2, &i.ino)
	stateSourceObject.Load(3, &i.mode)
	stateSourceObject.Load(4, &i.uid)
	stateSourceObject.Load(5, &i.gid)
	stateSourceObject.Load(6, &i.nlink)
}

func (s *slot) StateTypeName() string {
	return "pkg/sentry/fsimpl/kernfs.slot"
}

func (s *slot) StateFields() []string {
	return []string{
		"Name",
		"Dentry",
		"slotEntry",
	}
}

func (s *slot) beforeSave() {}

func (s *slot) StateSave(stateSinkObject state.Sink) {
	s.beforeSave()
	stateSinkObject.Save(0, &s.Name)
	stateSinkObject.Save(1, &s.Dentry)
	stateSinkObject.Save(2, &s.slotEntry)
}

func (s *slot) afterLoad() {}

func (s *slot) StateLoad(stateSourceObject state.Source) {
	stateSourceObject.Load(0, &s.Name)
	stateSourceObject.Load(1, &s.Dentry)
	stateSourceObject.Load(2, &s.slotEntry)
}

func (o *OrderedChildrenOptions) StateTypeName() string {
	return "pkg/sentry/fsimpl/kernfs.OrderedChildrenOptions"
}

func (o *OrderedChildrenOptions) StateFields() []string {
	return []string{
		"Writable",
	}
}

func (o *OrderedChildrenOptions) beforeSave() {}

func (o *OrderedChildrenOptions) StateSave(stateSinkObject state.Sink) {
	o.beforeSave()
	stateSinkObject.Save(0, &o.Writable)
}

func (o *OrderedChildrenOptions) afterLoad() {}

func (o *OrderedChildrenOptions) StateLoad(stateSourceObject state.Source) {
	stateSourceObject.Load(0, &o.Writable)
}

func (o *OrderedChildren) StateTypeName() string {
	return "pkg/sentry/fsimpl/kernfs.OrderedChildren"
}

func (o *OrderedChildren) StateFields() []string {
	return []string{
		"writable",
		"order",
		"set",
	}
}

func (o *OrderedChildren) beforeSave() {}

func (o *OrderedChildren) StateSave(stateSinkObject state.Sink) {
	o.beforeSave()
	stateSinkObject.Save(0, &o.writable)
	stateSinkObject.Save(1, &o.order)
	stateSinkObject.Save(2, &o.set)
}

func (o *OrderedChildren) afterLoad() {}

func (o *OrderedChildren) StateLoad(stateSourceObject state.Source) {
	stateSourceObject.Load(0, &o.writable)
	stateSourceObject.Load(1, &o.order)
	stateSourceObject.Load(2, &o.set)
}

func (r *renameAcrossDifferentImplementationsError) StateTypeName() string {
	return "pkg/sentry/fsimpl/kernfs.renameAcrossDifferentImplementationsError"
}

func (r *renameAcrossDifferentImplementationsError) StateFields() []string {
	return []string{}
}

func (r *renameAcrossDifferentImplementationsError) beforeSave() {}

func (r *renameAcrossDifferentImplementationsError) StateSave(stateSinkObject state.Sink) {
	r.beforeSave()
}

func (r *renameAcrossDifferentImplementationsError) afterLoad() {}

func (r *renameAcrossDifferentImplementationsError) StateLoad(stateSourceObject state.Source) {
}

func (i *InodeSymlink) StateTypeName() string {
	return "pkg/sentry/fsimpl/kernfs.InodeSymlink"
}

func (i *InodeSymlink) StateFields() []string {
	return []string{
		"InodeNotDirectory",
	}
}

func (i *InodeSymlink) beforeSave() {}

func (i *InodeSymlink) StateSave(stateSinkObject state.Sink) {
	i.beforeSave()
	stateSinkObject.Save(0, &i.InodeNotDirectory)
}

func (i *InodeSymlink) afterLoad() {}

func (i *InodeSymlink) StateLoad(stateSourceObject state.Source) {
	stateSourceObject.Load(0, &i.InodeNotDirectory)
}

func (s *StaticDirectory) StateTypeName() string {
	return "pkg/sentry/fsimpl/kernfs.StaticDirectory"
}

func (s *StaticDirectory) StateFields() []string {
	return []string{
		"InodeAttrs",
		"InodeDirectoryNoNewChildren",
		"InodeNoDynamicLookup",
		"InodeNoStatFS",
		"InodeNotSymlink",
		"OrderedChildren",
		"StaticDirectoryRefs",
		"locks",
		"fdOpts",
	}
}

func (s *StaticDirectory) beforeSave() {}

func (s *StaticDirectory) StateSave(stateSinkObject state.Sink) {
	s.beforeSave()
	stateSinkObject.Save(0, &s.InodeAttrs)
	stateSinkObject.Save(1, &s.InodeDirectoryNoNewChildren)
	stateSinkObject.Save(2, &s.InodeNoDynamicLookup)
	stateSinkObject.Save(3, &s.InodeNoStatFS)
	stateSinkObject.Save(4, &s.InodeNotSymlink)
	stateSinkObject.Save(5, &s.OrderedChildren)
	stateSinkObject.Save(6, &s.StaticDirectoryRefs)
	stateSinkObject.Save(7, &s.locks)
	stateSinkObject.Save(8, &s.fdOpts)
}

func (s *StaticDirectory) afterLoad() {}

func (s *StaticDirectory) StateLoad(stateSourceObject state.Source) {
	stateSourceObject.Load(0, &s.InodeAttrs)
	stateSourceObject.Load(1, &s.InodeDirectoryNoNewChildren)
	stateSourceObject.Load(2, &s.InodeNoDynamicLookup)
	stateSourceObject.Load(3, &s.InodeNoStatFS)
	stateSourceObject.Load(4, &s.InodeNotSymlink)
	stateSourceObject.Load(5, &s.OrderedChildren)
	stateSourceObject.Load(6, &s.StaticDirectoryRefs)
	stateSourceObject.Load(7, &s.locks)
	stateSourceObject.Load(8, &s.fdOpts)
}

func (a *AlwaysValid) StateTypeName() string {
	return "pkg/sentry/fsimpl/kernfs.AlwaysValid"
}

func (a *AlwaysValid) StateFields() []string {
	return []string{}
}

func (a *AlwaysValid) beforeSave() {}

func (a *AlwaysValid) StateSave(stateSinkObject state.Sink) {
	a.beforeSave()
}

func (a *AlwaysValid) afterLoad() {}

func (a *AlwaysValid) StateLoad(stateSourceObject state.Source) {
}

func (i *InodeNoStatFS) StateTypeName() string {
	return "pkg/sentry/fsimpl/kernfs.InodeNoStatFS"
}

func (i *InodeNoStatFS) StateFields() []string {
	return []string{}
}

func (i *InodeNoStatFS) beforeSave() {}

func (i *InodeNoStatFS) StateSave(stateSinkObject state.Sink) {
	i.beforeSave()
}

func (i *InodeNoStatFS) afterLoad() {}

func (i *InodeNoStatFS) StateLoad(stateSourceObject state.Source) {
}

func (f *Filesystem) StateTypeName() string {
	return "pkg/sentry/fsimpl/kernfs.Filesystem"
}

func (f *Filesystem) StateFields() []string {
	return []string{
		"vfsfs",
		"droppedDentries",
		"nextInoMinusOne",
	}
}

func (f *Filesystem) beforeSave() {}

func (f *Filesystem) StateSave(stateSinkObject state.Sink) {
	f.beforeSave()
	stateSinkObject.Save(0, &f.vfsfs)
	stateSinkObject.Save(1, &f.droppedDentries)
	stateSinkObject.Save(2, &f.nextInoMinusOne)
}

func (f *Filesystem) afterLoad() {}

func (f *Filesystem) StateLoad(stateSourceObject state.Source) {
	stateSourceObject.Load(0, &f.vfsfs)
	stateSourceObject.Load(1, &f.droppedDentries)
	stateSourceObject.Load(2, &f.nextInoMinusOne)
}

func (d *Dentry) StateTypeName() string {
	return "pkg/sentry/fsimpl/kernfs.Dentry"
}

func (d *Dentry) StateFields() []string {
	return []string{
		"DentryRefs",
		"vfsd",
		"flags",
		"parent",
		"name",
		"children",
		"inode",
	}
}

func (d *Dentry) beforeSave() {}

func (d *Dentry) StateSave(stateSinkObject state.Sink) {
	d.beforeSave()
	stateSinkObject.Save(0, &d.DentryRefs)
	stateSinkObject.Save(1, &d.vfsd)
	stateSinkObject.Save(2, &d.flags)
	stateSinkObject.Save(3, &d.parent)
	stateSinkObject.Save(4, &d.name)
	stateSinkObject.Save(5, &d.children)
	stateSinkObject.Save(6, &d.inode)
}

func (d *Dentry) afterLoad() {}

func (d *Dentry) StateLoad(stateSourceObject state.Source) {
	stateSourceObject.Load(0, &d.DentryRefs)
	stateSourceObject.Load(1, &d.vfsd)
	stateSourceObject.Load(2, &d.flags)
	stateSourceObject.Load(3, &d.parent)
	stateSourceObject.Load(4, &d.name)
	stateSourceObject.Load(5, &d.children)
	stateSourceObject.Load(6, &d.inode)
}

func (s *slotList) StateTypeName() string {
	return "pkg/sentry/fsimpl/kernfs.slotList"
}

func (s *slotList) StateFields() []string {
	return []string{
		"head",
		"tail",
	}
}

func (s *slotList) beforeSave() {}

func (s *slotList) StateSave(stateSinkObject state.Sink) {
	s.beforeSave()
	stateSinkObject.Save(0, &s.head)
	stateSinkObject.Save(1, &s.tail)
}

func (s *slotList) afterLoad() {}

func (s *slotList) StateLoad(stateSourceObject state.Source) {
	stateSourceObject.Load(0, &s.head)
	stateSourceObject.Load(1, &s.tail)
}

func (s *slotEntry) StateTypeName() string {
	return "pkg/sentry/fsimpl/kernfs.slotEntry"
}

func (s *slotEntry) StateFields() []string {
	return []string{
		"next",
		"prev",
	}
}

func (s *slotEntry) beforeSave() {}

func (s *slotEntry) StateSave(stateSinkObject state.Sink) {
	s.beforeSave()
	stateSinkObject.Save(0, &s.next)
	stateSinkObject.Save(1, &s.prev)
}

func (s *slotEntry) afterLoad() {}

func (s *slotEntry) StateLoad(stateSourceObject state.Source) {
	stateSourceObject.Load(0, &s.next)
	stateSourceObject.Load(1, &s.prev)
}

func (s *StaticDirectoryRefs) StateTypeName() string {
	return "pkg/sentry/fsimpl/kernfs.StaticDirectoryRefs"
}

func (s *StaticDirectoryRefs) StateFields() []string {
	return []string{
		"refCount",
	}
}

func (s *StaticDirectoryRefs) beforeSave() {}

func (s *StaticDirectoryRefs) StateSave(stateSinkObject state.Sink) {
	s.beforeSave()
	stateSinkObject.Save(0, &s.refCount)
}

func (s *StaticDirectoryRefs) afterLoad() {}

func (s *StaticDirectoryRefs) StateLoad(stateSourceObject state.Source) {
	stateSourceObject.Load(0, &s.refCount)
}

func (s *StaticSymlink) StateTypeName() string {
	return "pkg/sentry/fsimpl/kernfs.StaticSymlink"
}

func (s *StaticSymlink) StateFields() []string {
	return []string{
		"InodeAttrs",
		"InodeNoopRefCount",
		"InodeSymlink",
		"InodeNoStatFS",
		"target",
	}
}

func (s *StaticSymlink) beforeSave() {}

func (s *StaticSymlink) StateSave(stateSinkObject state.Sink) {
	s.beforeSave()
	stateSinkObject.Save(0, &s.InodeAttrs)
	stateSinkObject.Save(1, &s.InodeNoopRefCount)
	stateSinkObject.Save(2, &s.InodeSymlink)
	stateSinkObject.Save(3, &s.InodeNoStatFS)
	stateSinkObject.Save(4, &s.target)
}

func (s *StaticSymlink) afterLoad() {}

func (s *StaticSymlink) StateLoad(stateSourceObject state.Source) {
	stateSourceObject.Load(0, &s.InodeAttrs)
	stateSourceObject.Load(1, &s.InodeNoopRefCount)
	stateSourceObject.Load(2, &s.InodeSymlink)
	stateSourceObject.Load(3, &s.InodeNoStatFS)
	stateSourceObject.Load(4, &s.target)
}

func (s *syntheticDirectory) StateTypeName() string {
	return "pkg/sentry/fsimpl/kernfs.syntheticDirectory"
}

func (s *syntheticDirectory) StateFields() []string {
	return []string{
		"InodeAttrs",
		"InodeNoStatFS",
		"InodeNoopRefCount",
		"InodeNoDynamicLookup",
		"InodeNotSymlink",
		"OrderedChildren",
		"locks",
	}
}

func (s *syntheticDirectory) beforeSave() {}

func (s *syntheticDirectory) StateSave(stateSinkObject state.Sink) {
	s.beforeSave()
	stateSinkObject.Save(0, &s.InodeAttrs)
	stateSinkObject.Save(1, &s.InodeNoStatFS)
	stateSinkObject.Save(2, &s.InodeNoopRefCount)
	stateSinkObject.Save(3, &s.InodeNoDynamicLookup)
	stateSinkObject.Save(4, &s.InodeNotSymlink)
	stateSinkObject.Save(5, &s.OrderedChildren)
	stateSinkObject.Save(6, &s.locks)
}

func (s *syntheticDirectory) afterLoad() {}

func (s *syntheticDirectory) StateLoad(stateSourceObject state.Source) {
	stateSourceObject.Load(0, &s.InodeAttrs)
	stateSourceObject.Load(1, &s.InodeNoStatFS)
	stateSourceObject.Load(2, &s.InodeNoopRefCount)
	stateSourceObject.Load(3, &s.InodeNoDynamicLookup)
	stateSourceObject.Load(4, &s.InodeNotSymlink)
	stateSourceObject.Load(5, &s.OrderedChildren)
	stateSourceObject.Load(6, &s.locks)
}

func init() {
	state.Register((*DentryRefs)(nil))
	state.Register((*DynamicBytesFile)(nil))
	state.Register((*DynamicBytesFD)(nil))
	state.Register((*SeekEndConfig)(nil))
	state.Register((*GenericDirectoryFDOptions)(nil))
	state.Register((*GenericDirectoryFD)(nil))
	state.Register((*InodeNoopRefCount)(nil))
	state.Register((*InodeDirectoryNoNewChildren)(nil))
	state.Register((*InodeNotDirectory)(nil))
	state.Register((*InodeNoDynamicLookup)(nil))
	state.Register((*InodeNotSymlink)(nil))
	state.Register((*InodeAttrs)(nil))
	state.Register((*slot)(nil))
	state.Register((*OrderedChildrenOptions)(nil))
	state.Register((*OrderedChildren)(nil))
	state.Register((*renameAcrossDifferentImplementationsError)(nil))
	state.Register((*InodeSymlink)(nil))
	state.Register((*StaticDirectory)(nil))
	state.Register((*AlwaysValid)(nil))
	state.Register((*InodeNoStatFS)(nil))
	state.Register((*Filesystem)(nil))
	state.Register((*Dentry)(nil))
	state.Register((*slotList)(nil))
	state.Register((*slotEntry)(nil))
	state.Register((*StaticDirectoryRefs)(nil))
	state.Register((*StaticSymlink)(nil))
	state.Register((*syntheticDirectory)(nil))
}