// Copyright 2021 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// All tests in this file rely on being about to mount and unmount cgroupfs,
// which isn't expected to work, or be safe on a general linux system.

#include <unistd.h>

#include "gtest/gtest.h"
#include "absl/container/flat_hash_map.h"
#include "absl/container/flat_hash_set.h"
#include "absl/strings/str_split.h"
#include "test/util/capability_util.h"
#include "test/util/fs_util.h"
#include "test/util/mount_util.h"
#include "test/util/temp_path.h"
#include "test/util/test_util.h"

namespace gvisor {
namespace testing {
namespace {

using ::testing::_;

class Cgroup {
 public:
  Cgroup(string path) : cgroup_path_(path) {
    id_ = ++Cgroup::next_id_;
    std::cerr << absl::StreamFormat("[cg#%d] <= %s", id_, cgroup_path_)
              << std::endl;
  }

  uint64_t id() const { return id_; }

  string Relpath(absl::string_view leaf) const {
    return JoinPath(cgroup_path_, leaf);
  }

  PosixErrorOr<std::string> ReadControlFile(absl::string_view name) const {
    std::string buf;
    RETURN_IF_ERRNO(GetContents(Relpath(name), &buf));

    const string alias_path = absl::StrFormat("[cg#%d]/%s", id_, name);
    std::cerr << absl::StreamFormat("<contents of %s>", alias_path)
              << std::endl;
    std::cerr << buf;
    std::cerr << absl::StreamFormat("<end of %s>", alias_path) << std::endl;

    return buf;
  }

  PosixErrorOr<int64_t> ReadIntegerControlFile(absl::string_view name) const {
    ASSIGN_OR_RETURN_ERRNO(const string buf, ReadControlFile(name));
    ASSIGN_OR_RETURN_ERRNO(const int64_t val, Atoi<int64_t>(buf));
    return val;
  }

  PosixErrorOr<absl::flat_hash_set<pid_t>> Procs() const {
    ASSIGN_OR_RETURN_ERRNO(std::string buf, ReadControlFile("cgroup.procs"));
    return ParsePIDList(buf);
  }

  PosixErrorOr<absl::flat_hash_set<pid_t>> Tasks() const {
    ASSIGN_OR_RETURN_ERRNO(std::string buf, ReadControlFile("tasks"));
    return ParsePIDList(buf);
  }

  PosixError ContainsCallingProcess() const {
    ASSIGN_OR_RETURN_ERRNO(const absl::flat_hash_set<pid_t> procs, Procs());
    ASSIGN_OR_RETURN_ERRNO(const absl::flat_hash_set<pid_t> tasks, Tasks());
    const pid_t pid = getpid();
    const pid_t tid = syscall(SYS_gettid);
    if (!procs.contains(pid)) {
      return PosixError(
          ENOENT, absl::StrFormat("Cgroup doesn't contain process %d", pid));
    }
    if (!tasks.contains(tid)) {
      return PosixError(ENOENT,
                        absl::StrFormat("Cgroup doesn't contain task %d", tid));
    }
    return NoError();
  }

 private:
  PosixErrorOr<absl::flat_hash_set<pid_t>> ParsePIDList(
      absl::string_view data) const {
    absl::flat_hash_set<pid_t> res;
    std::vector<absl::string_view> lines = absl::StrSplit(data, '\n');
    for (const std::string_view& line : lines) {
      if (line.empty()) {
        continue;
      }
      ASSIGN_OR_RETURN_ERRNO(const int32_t pid, Atoi<int32_t>(line));
      res.insert(static_cast<pid_t>(pid));
    }
    return res;
  }

  static int64_t next_id_;
  int64_t id_;
  const std::string cgroup_path_;
};

int64_t Cgroup::next_id_ = 0;

class Mounter {
 public:
  Mounter(TempPath root) : root_(std::move(root)) {}

  PosixErrorOr<Cgroup> MountCgroupfs(std::string mopts) {
    ASSIGN_OR_RETURN_ERRNO(TempPath mountpoint,
                           TempPath::CreateDirIn(root_.path()));
    ASSIGN_OR_RETURN_ERRNO(
        Cleanup mount, Mount("none", mountpoint.path(), "cgroup", 0, mopts, 0));
    const std::string mountpath = mountpoint.path();
    std::cerr << absl::StreamFormat(
                     "Mount(\"none\", \"%s\", \"cgroup\", 0, \"%s\", 0) => OK",
                     mountpath, mopts)
              << std::endl;
    Cgroup cg = Cgroup(mountpath);
    mountpoints_[cg.id()] = std::move(mountpoint);
    mounts_[cg.id()] = std::move(mount);
    return cg;
  }

  PosixError Unmount(const Cgroup& c) {
    auto mount = mounts_.find(c.id());
    auto mountpoint = mountpoints_.find(c.id());

    if (mount == mounts_.end() || mountpoint == mountpoints_.end()) {
      return PosixError(
          ESRCH, absl::StrFormat("No mount found for cgroupfs containing cg#%d",
                                 c.id()));
    }

    std::cerr << absl::StreamFormat("Unmount([cg#%d])", c.id()) << std::endl;

    // Simply delete the entries, their destructors will unmount and delete the
    // mountpoint. Note the order is important to avoid errors: mount then
    // mountpoint.
    mounts_.erase(mount);
    mountpoints_.erase(mountpoint);

    return NoError();
  }

 private:
  // The destruction order of these members avoids errors during cleanup. We
  // first unmount (by executing the mounts_ cleanups), then delete the
  // mountpoint subdirs, then delete the root.
  TempPath root_;
  absl::flat_hash_map<int64_t, TempPath> mountpoints_;
  absl::flat_hash_map<int64_t, Cleanup> mounts_;
};

bool CgroupTestUnavailable() {
  return !IsRunningOnGvisor() || IsRunningWithVFS1() ||
         !TEST_CHECK_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_ADMIN));
}

TEST(Cgroup, MountSucceeds) {
  SKIP_IF(CgroupTestUnavailable());

  Mounter m(ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir()));
  Cgroup c = ASSERT_NO_ERRNO_AND_VALUE(m.MountCgroupfs(""));
  EXPECT_NO_ERRNO(c.ContainsCallingProcess());
}

TEST(Cgroup, SeparateMounts) {
  SKIP_IF(CgroupTestUnavailable());

  Mounter m(ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir()));
  Cgroup memroot = ASSERT_NO_ERRNO_AND_VALUE(m.MountCgroupfs("memory"));
  Cgroup cpuroot = ASSERT_NO_ERRNO_AND_VALUE(m.MountCgroupfs("cpu"));
  EXPECT_NO_ERRNO(memroot.ContainsCallingProcess());
  EXPECT_NO_ERRNO(cpuroot.ContainsCallingProcess());
}

TEST(Cgroup, ProcsAndTasks) {
  SKIP_IF(CgroupTestUnavailable());

  Mounter m(ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir()));
  Cgroup c = ASSERT_NO_ERRNO_AND_VALUE(m.MountCgroupfs(""));
  absl::flat_hash_set<pid_t> pids = ASSERT_NO_ERRNO_AND_VALUE(c.Procs());
  absl::flat_hash_set<pid_t> tids = ASSERT_NO_ERRNO_AND_VALUE(c.Tasks());

  EXPECT_GE(tids.size(), pids.size()) << "Found more processes than threads";

  // Pids should be a strict subset of tids.
  for (auto it = pids.begin(); it != pids.end(); ++it) {
    EXPECT_TRUE(tids.contains(*it))
        << absl::StreamFormat("Have pid %d, but no such tid", *it);
  }
}

TEST(Cgroup, ControllersMustBeInUniqueHierarchy) {
  SKIP_IF(CgroupTestUnavailable());

  Mounter m(ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir()));
  // Hierarchy #1: all controllers.
  Cgroup all = ASSERT_NO_ERRNO_AND_VALUE(m.MountCgroupfs(""));
  // Hierarchy #2: memory.
  //
  // This should conflict since memory is already in hierarchy #1, and the two
  // hierarchies have different sets of controllers, so this mount can't be a
  // view into hierarchy #1.
  EXPECT_THAT(m.MountCgroupfs("memory"), PosixErrorIs(EBUSY, _))
      << "Memory controller mounted on two hierarchies";
  EXPECT_THAT(m.MountCgroupfs("cpu"), PosixErrorIs(EBUSY, _))
      << "CPU controller mounted on two hierarchies";
}

TEST(Cgroup, UnmountFreesControllers) {
  SKIP_IF(CgroupTestUnavailable());
  Mounter m(ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir()));
  Cgroup all = ASSERT_NO_ERRNO_AND_VALUE(m.MountCgroupfs(""));
  // All controllers are now attached to all's hierarchy. Attempting new mount
  // with any individual controller should fail.
  EXPECT_THAT(m.MountCgroupfs("memory"), PosixErrorIs(EBUSY, _))
      << "Memory controller mounted on two hierarchies";

  // Unmount the "all" hierarchy. This should enable any controller to be
  // mounted on a new hierarchy again.
  ASSERT_NO_ERRNO(m.Unmount(all));
  EXPECT_NO_ERRNO(m.MountCgroupfs("memory"));
  EXPECT_NO_ERRNO(m.MountCgroupfs("cpu"));
}

TEST(Cgroup, OnlyContainsControllerSpecificFiles) {
  SKIP_IF(CgroupTestUnavailable());
  Mounter m(ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir()));
  Cgroup mem = ASSERT_NO_ERRNO_AND_VALUE(m.MountCgroupfs("memory"));
  EXPECT_THAT(Exists(mem.Relpath("memory.usage_in_bytes")),
              IsPosixErrorOkAndHolds(true));
  // CPU files shouldn't exist in memory cgroups.
  EXPECT_THAT(Exists(mem.Relpath("cpu.cfs_period_us")),
              IsPosixErrorOkAndHolds(false));
  EXPECT_THAT(Exists(mem.Relpath("cpu.cfs_quota_us")),
              IsPosixErrorOkAndHolds(false));
  EXPECT_THAT(Exists(mem.Relpath("cpu.shares")), IsPosixErrorOkAndHolds(false));

  Cgroup cpu = ASSERT_NO_ERRNO_AND_VALUE(m.MountCgroupfs("cpu"));
  EXPECT_THAT(Exists(cpu.Relpath("cpu.cfs_period_us")),
              IsPosixErrorOkAndHolds(true));
  EXPECT_THAT(Exists(cpu.Relpath("cpu.cfs_quota_us")),
              IsPosixErrorOkAndHolds(true));
  EXPECT_THAT(Exists(cpu.Relpath("cpu.shares")), IsPosixErrorOkAndHolds(true));
  // Memory files shouldn't exist in cpu cgroups.
  EXPECT_THAT(Exists(cpu.Relpath("memory.usage_in_bytes")),
              IsPosixErrorOkAndHolds(false));
}

TEST(MemoryCgroup, MemoryUsageInBytes) {
  SKIP_IF(CgroupTestUnavailable());

  Mounter m(ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir()));
  Cgroup c = ASSERT_NO_ERRNO_AND_VALUE(m.MountCgroupfs("memory"));
  uint64_t usage = ASSERT_NO_ERRNO_AND_VALUE(
      c.ReadIntegerControlFile("memory.usage_in_bytes"));
  EXPECT_GT(usage, 0);
}

TEST(CPUCgroup, ControlFilesHaveDefaultValues) {
  SKIP_IF(CgroupTestUnavailable());

  Mounter m(ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir()));
  Cgroup c = ASSERT_NO_ERRNO_AND_VALUE(m.MountCgroupfs("cpu"));
  uint64_t quota =
      ASSERT_NO_ERRNO_AND_VALUE(c.ReadIntegerControlFile("cpu.cfs_quota_us"));
  uint64_t period =
      ASSERT_NO_ERRNO_AND_VALUE(c.ReadIntegerControlFile("cpu.cfs_period_us"));
  uint64_t shares =
      ASSERT_NO_ERRNO_AND_VALUE(c.ReadIntegerControlFile("cpu.shares"));
  // Default values.
  EXPECT_EQ(quota, -1);
  EXPECT_EQ(period, 100000);
  EXPECT_EQ(shares, 1024);
}

// Represents a line from /proc/cgroups.
struct CgroupsEntry {
  std::string subsys_name;
  uint32_t hierarchy;
  uint64_t num_cgroups;
  bool enabled;
};

constexpr char kProcCgroupsHeader[] =
    "#subsys_name\thierarchy\tnum_cgroups\tenabled";

// Returns a parsed representation of /proc/cgroups.
PosixErrorOr<absl::flat_hash_map<std::string, CgroupsEntry>>
ProcCgroupsEntries() {
  std::string content;
  RETURN_IF_ERRNO(GetContents("/proc/cgroups", &content));

  bool found_header = false;
  absl::flat_hash_map<std::string, CgroupsEntry> entries;
  std::vector<std::string> lines = absl::StrSplit(content, '\n');
  std::cerr << "<contents of /proc/cgroups>" << std::endl;
  for (const std::string& line : lines) {
    std::cerr << line << std::endl;

    if (!found_header) {
      EXPECT_EQ(line, kProcCgroupsHeader);
      found_header = true;
      continue;
    }
    if (line.empty()) {
      continue;
    }

    // Parse a single entry from /proc/cgroups.
    //
    // Example entries, fields are tab separated in the real file:
    //
    // #subsys_name    hierarchy       num_cgroups     enabled
    // cpuset  12      35      1
    // cpu     3       222     1
    //   ^     ^       ^       ^
    //   0     1       2       3

    CgroupsEntry entry;
    std::vector<std::string> fields =
        StrSplit(line, absl::ByAnyChar(": \t"), absl::SkipEmpty());

    entry.subsys_name = fields[0];
    ASSIGN_OR_RETURN_ERRNO(entry.hierarchy, Atoi<uint32_t>(fields[1]));
    ASSIGN_OR_RETURN_ERRNO(entry.num_cgroups, Atoi<uint64_t>(fields[2]));
    ASSIGN_OR_RETURN_ERRNO(const int enabled, Atoi<int>(fields[3]));
    entry.enabled = enabled != 0;

    entries[entry.subsys_name] = entry;
  }
  std::cerr << "<end of /proc/cgroups>" << std::endl;

  return entries;
}

TEST(ProcCgroups, Empty) {
  SKIP_IF(CgroupTestUnavailable());

  absl::flat_hash_map<string, CgroupsEntry> entries =
      ASSERT_NO_ERRNO_AND_VALUE(ProcCgroupsEntries());
  // No cgroups mounted yet, we should have no entries.
  EXPECT_TRUE(entries.empty());
}

TEST(ProcCgroups, ProcCgroupsEntries) {
  SKIP_IF(CgroupTestUnavailable());

  Mounter m(ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir()));

  Cgroup mem = ASSERT_NO_ERRNO_AND_VALUE(m.MountCgroupfs("memory"));
  absl::flat_hash_map<string, CgroupsEntry> entries =
      ASSERT_NO_ERRNO_AND_VALUE(ProcCgroupsEntries());
  EXPECT_EQ(entries.size(), 1);
  ASSERT_TRUE(entries.contains("memory"));
  CgroupsEntry mem_e = entries["memory"];
  EXPECT_EQ(mem_e.subsys_name, "memory");
  EXPECT_GE(mem_e.hierarchy, 1);
  // Expect a single root cgroup.
  EXPECT_EQ(mem_e.num_cgroups, 1);
  // Cgroups are currently always enabled when mounted.
  EXPECT_TRUE(mem_e.enabled);

  // Add a second cgroup, and check for new entry.

  Cgroup cpu = ASSERT_NO_ERRNO_AND_VALUE(m.MountCgroupfs("cpu"));
  entries = ASSERT_NO_ERRNO_AND_VALUE(ProcCgroupsEntries());
  EXPECT_EQ(entries.size(), 2);
  EXPECT_TRUE(entries.contains("memory"));  // Still have memory entry.
  ASSERT_TRUE(entries.contains("cpu"));
  CgroupsEntry cpu_e = entries["cpu"];
  EXPECT_EQ(cpu_e.subsys_name, "cpu");
  EXPECT_GE(cpu_e.hierarchy, 1);
  EXPECT_EQ(cpu_e.num_cgroups, 1);
  EXPECT_TRUE(cpu_e.enabled);

  // Separate hierarchies, since controllers were mounted separately.
  EXPECT_NE(mem_e.hierarchy, cpu_e.hierarchy);
}

TEST(ProcCgroups, UnmountRemovesEntries) {
  SKIP_IF(CgroupTestUnavailable());

  Mounter m(ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir()));
  Cgroup cg = ASSERT_NO_ERRNO_AND_VALUE(m.MountCgroupfs("cpu,memory"));
  absl::flat_hash_map<string, CgroupsEntry> entries =
      ASSERT_NO_ERRNO_AND_VALUE(ProcCgroupsEntries());
  EXPECT_EQ(entries.size(), 2);

  ASSERT_NO_ERRNO(m.Unmount(cg));

  entries = ASSERT_NO_ERRNO_AND_VALUE(ProcCgroupsEntries());
  EXPECT_TRUE(entries.empty());
}

// Represents a line from /proc/<pid>/cgroup.
struct PIDCgroupEntry {
  uint32_t hierarchy;
  std::string controllers;
  std::string path;
};

// Returns a parsed representation of /proc/<pid>/cgroup.
PosixErrorOr<absl::flat_hash_map<std::string, PIDCgroupEntry>>
ProcPIDCgroupEntries(pid_t pid) {
  const std::string path = absl::StrFormat("/proc/%d/cgroup", pid);
  std::string content;
  RETURN_IF_ERRNO(GetContents(path, &content));

  absl::flat_hash_map<std::string, PIDCgroupEntry> entries;
  std::vector<std::string> lines = absl::StrSplit(content, '\n');

  std::cerr << absl::StreamFormat("<contents of %s>", path) << std::endl;
  for (const std::string& line : lines) {
    std::cerr << line << std::endl;

    if (line.empty()) {
      continue;
    }

    // Parse a single entry from /proc/<pid>/cgroup.
    //
    // Example entries:
    //
    // 2:cpu:/path/to/cgroup
    // 1:memory:/

    PIDCgroupEntry entry;
    std::vector<std::string> fields =
        absl::StrSplit(line, absl::ByChar(':'), absl::SkipEmpty());

    ASSIGN_OR_RETURN_ERRNO(entry.hierarchy, Atoi<uint32_t>(fields[0]));
    entry.controllers = fields[1];
    entry.path = fields[2];

    entries[entry.controllers] = entry;
  }
  std::cerr << absl::StreamFormat("<end of %s>", path) << std::endl;

  return entries;
}

TEST(ProcPIDCgroup, Empty) {
  SKIP_IF(CgroupTestUnavailable());

  absl::flat_hash_map<std::string, PIDCgroupEntry> entries =
      ASSERT_NO_ERRNO_AND_VALUE(ProcPIDCgroupEntries(getpid()));
  EXPECT_TRUE(entries.empty());
}

TEST(ProcPIDCgroup, Entries) {
  SKIP_IF(CgroupTestUnavailable());

  Mounter m(ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir()));
  Cgroup c = ASSERT_NO_ERRNO_AND_VALUE(m.MountCgroupfs("memory"));

  absl::flat_hash_map<std::string, PIDCgroupEntry> entries =
      ASSERT_NO_ERRNO_AND_VALUE(ProcPIDCgroupEntries(getpid()));
  EXPECT_EQ(entries.size(), 1);
  PIDCgroupEntry mem_e = entries["memory"];
  EXPECT_GE(mem_e.hierarchy, 1);
  EXPECT_EQ(mem_e.controllers, "memory");
  EXPECT_EQ(mem_e.path, "/");

  Cgroup c1 = ASSERT_NO_ERRNO_AND_VALUE(m.MountCgroupfs("cpu"));
  entries = ASSERT_NO_ERRNO_AND_VALUE(ProcPIDCgroupEntries(getpid()));
  EXPECT_EQ(entries.size(), 2);
  EXPECT_TRUE(entries.contains("memory"));  // Still have memory entry.
  PIDCgroupEntry cpu_e = entries["cpu"];
  EXPECT_GE(cpu_e.hierarchy, 1);
  EXPECT_EQ(cpu_e.controllers, "cpu");
  EXPECT_EQ(cpu_e.path, "/");

  // Separate hierarchies, since controllers were mounted separately.
  EXPECT_NE(mem_e.hierarchy, cpu_e.hierarchy);
}

TEST(ProcPIDCgroup, UnmountRemovesEntries) {
  SKIP_IF(CgroupTestUnavailable());

  Mounter m(ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir()));
  Cgroup all = ASSERT_NO_ERRNO_AND_VALUE(m.MountCgroupfs(""));

  absl::flat_hash_map<std::string, PIDCgroupEntry> entries =
      ASSERT_NO_ERRNO_AND_VALUE(ProcPIDCgroupEntries(getpid()));
  EXPECT_GT(entries.size(), 0);

  ASSERT_NO_ERRNO(m.Unmount(all));

  entries = ASSERT_NO_ERRNO_AND_VALUE(ProcPIDCgroupEntries(getpid()));
  EXPECT_TRUE(entries.empty());
}

TEST(ProcCgroup, PIDCgroupMatchesCgroups) {
  SKIP_IF(CgroupTestUnavailable());

  Mounter m(ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir()));
  Cgroup c = ASSERT_NO_ERRNO_AND_VALUE(m.MountCgroupfs("memory"));
  Cgroup c1 = ASSERT_NO_ERRNO_AND_VALUE(m.MountCgroupfs("cpu"));

  absl::flat_hash_map<string, CgroupsEntry> cgroups_entries =
      ASSERT_NO_ERRNO_AND_VALUE(ProcCgroupsEntries());
  absl::flat_hash_map<std::string, PIDCgroupEntry> pid_entries =
      ASSERT_NO_ERRNO_AND_VALUE(ProcPIDCgroupEntries(getpid()));

  CgroupsEntry cgroup_mem = cgroups_entries["memory"];
  PIDCgroupEntry pid_mem = pid_entries["memory"];

  EXPECT_EQ(cgroup_mem.hierarchy, pid_mem.hierarchy);
}

TEST(ProcCgroup, MultiControllerHierarchy) {
  SKIP_IF(CgroupTestUnavailable());

  Mounter m(ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir()));
  Cgroup c = ASSERT_NO_ERRNO_AND_VALUE(m.MountCgroupfs("memory,cpu"));

  absl::flat_hash_map<string, CgroupsEntry> cgroups_entries =
      ASSERT_NO_ERRNO_AND_VALUE(ProcCgroupsEntries());

  CgroupsEntry mem_e = cgroups_entries["memory"];
  CgroupsEntry cpu_e = cgroups_entries["cpu"];

  // Both controllers should have the same hierarchy ID.
  EXPECT_EQ(mem_e.hierarchy, cpu_e.hierarchy);

  absl::flat_hash_map<std::string, PIDCgroupEntry> pid_entries =
      ASSERT_NO_ERRNO_AND_VALUE(ProcPIDCgroupEntries(getpid()));

  // Expecting an entry listing both controllers, that matches the previous
  // hierarchy ID. Note that the controllers are listed in alphabetical order.
  PIDCgroupEntry pid_e = pid_entries["cpu,memory"];
  EXPECT_EQ(pid_e.hierarchy, mem_e.hierarchy);
}

}  // namespace
}  // namespace testing
}  // namespace gvisor
