---
layout: post
title: "[DragonSector Teaser:Production] Analyzing C sources."
comments: true
--- 

# The task.

![](/assets/files/ctf/2018/dragonsector/logo.png)

  * [original link](https://ctf.dragonsector.pl/?challenges)
  * [attach](/assets/files/ctf/2018/dragonsector/lyrics.cc)
  * [ctftime](https://ctftime.org/event/648)


# Analyzing the source.

The only file we were given is [lyrics.cc](/assets/files/ctf/2018/dragonsector/lyrics.cc). Let's make a quick walk-through. 

```
static bool list_songs() {
  char buffer[32] = { /* zero padding */ };

  printf("Band: ");
  read_line(STDIN_FILENO, buffer, sizeof(buffer));

  // Never trust user input!!
  if (!sanitize_path(buffer)) {
    printf("[-] Nice try!\n");
    return false;
  }

  char path[48] = "./data/";
  strncat(path, buffer, sizeof(path) - 7);

  std::vector<std::string> songs;
  if (!list_files(path, &songs)) {
    return false;
  }
...

```

This `zero padding` looks weird, but when we analyze it more deeply, it turns out not very useful, because even if we force somehow `read_line()` not to modify buffer, that buffer will be passed to `list_files()`, which will compare that data with files on disk and print it, if files exists.


The second weird part is a deletion of values in the vector:

```
  memmove(&globals::records[idx], &globals::records[idx + 1],
          (globals::records.size() - idx - 1) * sizeof(int));
  globals::records.pop_back();
```

But if we will analyze it more deeply, we can notice just shifting of values and pop from the end. 

Another interesting plase is `sanitize_path()`:

```
static bool sanitize_path(char *buffer) {
  if (strstr(buffer, "../") != NULL) {
    return false;
  }

  return true;
}
```

`../` is filtered, but `..` is not, so we can try use it:

```
$ nc lyrics.hackable.software 4141
Welcome to the Lyrics Explorer!
Command> songs
Band: ..
lyrics
data
lyrics.cc
flag
Command> 
```

Yep, it works indeed. It's our first useful bug.

Let's try to read that files. 

```
$ nc lyrics.hackable.software 4141
Welcome to the Lyrics Explorer!
Command> open
Band: ..
Song: lyrics 
[+] Opened the lyrics as new record 0
Command> read
Record ID: 0
ELF........
```

Nice, it works just great. 

At this point, I'm stuck for a while. I'm felt that we need to trigger this branch in `open_lyrics()` somehow:

```
  // Better safe then sorry. Make sure that the path also doesn't point to a
  // symbolic link.
  int fd2 = open(path, O_RDONLY | O_NOFOLLOW);
  if (fd2 == -1) {
    printf("[-] Detected attempt to open a symbolic link!\n");

    // Some kind of attack detected?
    return true;
  }
  close(fd2);

```

This is the only possibility in the code to open the flag file. I had enumerated all files and dirs to check if there is any symlink. There were no symlinks :(.

Suddenly my teammate proposed the idea, that if we could leak file descriptors and reach a limit of 32, we can trigger that brunch.

```
  rlim.rlim_cur = rlim.rlim_max = 32;
  setrlimit(RLIMIT_NOFILE, &rlim);
```

But there were no resource leaks, until some interesting place:

```
  // Let's make sure we're not disclosing any sensitive data due to potential
  // bugs in the program.
  if (bytes_read > 0) {
    if (strstr(buffer, "DrgnS")) {
      printf("[-] Attack detected and stopped!\n");

      assert(close(globals::records[idx]) == 0);
      memmove(&globals::records[idx], &globals::records[idx + 1],
              (globals::records.size() - idx - 1) * sizeof(int));
      globals::records.pop_back();
      return true;
    }
  }
```

Let's check `assert()`'s manual:

>DESCRIPTION
>       If  the  macro NDEBUG was defined at the moment <assert.h> was last included, the macro assert() generates no code, and hence does nothing at all.  Otherwise, the macro
>       assert() prints an error message to standard error and terminates the program by calling abort(3) if expression is false (i.e., compares equal to zero).

Indeed asserts can be disabled in the remote build. After checking, it turns out that they were disabled! So we could leak resources and open the flag file.

I thought it's the end, but the flag file itself is containing "DrgnS" string, so we can't read it directly. 

Another bug I discovered when red files were that if you reach the end of the file, there were no any errors, I just continuously received last string of file. Why is that?

```
static ssize_t read_line_buffered(int fd, char *buffer, size_t size) {
  if (size == 0) {
    return -1;
  }

  ssize_t ret = read(fd, buffer, size - 1);

  if (ret <= 0) {
    return ret;
  }

  buffer[ret] = '\0';

  for (ssize_t i = 0; i < ret; i++) {
    if (buffer[i] == '\0') {
      buffer[i] = '.';
    } else if (buffer[i] == '\n') {
      buffer[i] = '\0';
      lseek(fd, -(ret - i - 1), SEEK_CUR);
      return i;
    }
  }

  return ret;
}

```

That's because we hit `ret <= 0` branch, and we just printing `buffer` variable of caller's function:

```
static bool read_lyrics() {
  printf("Record ID: ");
  int idx = load_int();

  if (idx < 0 || idx >= globals::records.size()) {
    return false;
  }

  char buffer[4096];
  ssize_t bytes_read = read_line_buffered(globals::records[idx],
                                          buffer, sizeof(buffer));
```

But wait! You said we can red flag? Where it would be? 

Yes, it would be placed in that buffer. So we could just read some random lyrics file, until `read()` will return an error, then we could read the flag, get some error again, and call read of the file with EOF, this will print our flag finally.

The flag is `DrgnS{Huh_Ass3rti0n5_can_b3_unre1i4b13}`

Full expoit is [here](/assets/files/ctf/2018/dragonsector/xpwn.py).