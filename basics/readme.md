# __basics__
## __commands__

### cat
cat is used to print contents of a file.

Useful args: -n to show line numbers

-s to not see empty lines

https://man7.org/linux/man-pages/man1/cat.1.html
### head
head is used to output first 10 lines (default) of a file.

Useful args: -n NUMBER can be used to print a specific number of lines

https://man7.org/linux/man-pages/man1/head.1.html

### tail
Similar to head but prints last 10 lines (default) of a file.

Useful args: -n NUMBER can be used to print a specific number of lines

-f can be used to follow a file as the file gets more data added to it

https://man7.org/linux/man-pages/man1/tail.1.html

### wc
wc can be used to count things such as lines, words, and etc.

Useful args: -l prints number of lines

https://man7.org/linux/man-pages/man1/wc.1.html

### sort
sort can be used to sort lines.

Useful args: -b ignore leading blanks

-f ignore case

-n numeric sort / sort based on numbers

-r reverse sort

https://man7.org/linux/man-pages/man1/sort.1.html

### uniq
uniq lets you print / count unique lines

Useful args: -c print count

-i ignore case

-d only print duplicate lines

-u only print unique lines

https://man7.org/linux/man-pages/man1/uniq.1.html

### more
more is similar to cat but instead of printing out a file and exiting, it will let you scroll down through a file one line at a time or one page at a time. Use less instead...


https://man7.org/linux/man-pages/man1/more.1.html

### less
less is similar to more but it lets you scroll up and down through the output. less also lets you search through the output.

https://man7.org/linux/man-pages/man1/less.1.html

### awk
awk is "pattern scanning and processing language". awk can do many things but one of the use cases for log analysis can be to parse logs and only print specific things or build strings. awk does have search and filter capability as well.

Useful args: -F this can be used to specific a seperator when parsing logs

https://man7.org/linux/man-pages/man1/awk.1p.html

https://mauricius.dev/parse-log-files-with-awk/

### cut
cut lets you cut part of a file/input and only show certain parts. for example, you can cut a csv file and look at only certain fields.

Useful args: -d DELIMITER, this is what you can define delimiter with for a certain file/values.

-f - this defines the field or fields you want to print

--complement - this prints the inverse of defined fields

https://man7.org/linux/man-pages/man1/cut.1.html

### sed
sed allows for editing of data. you can do things such as search and replace or delete. 

https://man7.org/linux/man-pages/man1/sed.1.html

https://www.geeksforgeeks.org/sed-command-in-linux-unix-with-examples/

### tr
tr lets you translate/modify input. 

https://man7.org/linux/man-pages/man1/tr.1.

https://www.geeksforgeeks.org/tr-command-in-unix-linux-with-examples/

### grep
grep lets you search through data. 

Useful args: -r to recursively read multiple files in a directory or directories

-i ignore case

-v invert match - basically show everything that didn't match

https://man7.org/linux/man-pages/man1/grep.1.html

### watch
watch command isn't specifically for processing logs but it can be helpful. watch command runs a specific command or sets of commands periodically.

Useful args: -n SECONDS this defines how often to run a command

-d this highlights the differences

https://man7.org/linux/man-pages/man1/watch.1.html

### tee
tee command lets you print output to screen as well as write output to a file.

Useful args: -a append to a file instead of overwriting

https://man7.org/linux/man-pages/man1/tee.1.html

## __log types and examples__
### text
This would be just text file/ text logs. Text logs can be in different formats. If you look in linux logs folder, you may encounter various log files that have different formats/structures.

### csv, tsv, pipe seperated
csv, tsv, pipe seperated files usually have headers, like in a table which are also seperated by the seperator along with the values.

CSV is comma-separated values. there is a comma `,` between each value in a line. A lot of tools and products output csv file. 

TSV is tab-separated values. it's similar to csv but a tab is used instead of comma. Zeek/bro uses tsv format for example.

pipe seperated is values seperated by a pipe `|`. 

tab seperated logs exist as well.

you can pretty much use any value as a seperator if you wanted to.

https://en.wikipedia.org/wiki/Delimiter-separated_values

### json
json log file would have json in it. some applications may log one json event on different line and some applications may log json event on just one line. Suricata eve log file for example uses json for logging. Zeek/bro can as well.