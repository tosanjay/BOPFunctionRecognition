Introduction:
=============
The following abstract from the original paper "Sanjay Rawat and Laurent Mounier, "Finding Buffer Overflow Inducing Loops in Binary Executables",
In Proc. of the IEEE International Conference on Software Security and Reliability (SERE) 2012, June 2012, Washington DC, USA", gives the hint about this tool:

Abstract—Vulnerability analysis is one among the important
components of overall software assurance practice. The main
aim of vulnerability analysis is to find patterns in software
that indicate possible vulnerabilities. Buffer overflow (BoF) is
one of such vulnerabilities that has managed to top the list
of vulnerabilities. A general practice to find BoF is to look
for the presence of certain functions that manipulate string
buffers. strcpy family of C/C++ functions is an example of
such functions. A simple analysis of such functions reveals that
data is moved from one buffer to another buffer within a
loop without considering destination buffer size. We argue that
similar behaviour may also be present in other functions that
are coded separately and therefore, are equally vulnerable. In
the present report, we investigate the detection of such functions
by finding loops that exhibit similar behavior. We call such loops
as Buffer Overflow Inducing Loops (BOIL) mainly from buffer
overflow vulnerability standpoint. We implemented our solution
and analyzed it on real-world x86 binary executables. The results
obtained show that this (simple but yet efficient) vulnerability
pattern may provide a drastic reduction of the part of the code
to be analysed, while allowing to detect real vulnerabilities.

Software Requirements:
=====================
1. BinNavi Version 4 (Note: version 3 uses MySQL databases, whereas from v4 onwards, BinNavi uses PostGreSQL)
2. IDA Pro v 6
3. Jython

Installation:
============
No installation as such. In order to anlayze a binary file, follow the steps:

A- Creating IDA pro IDB file
1. drag-n-drop executable into the opened IDA Pro pane.
6. In the following IDA pro window, uncheck "make imports segment" and then OK.
7. Wait until IDApro finishes its analysis and then close IDApro. It will ask to save the analysis and choose "yes"
8. The previous step will create a test.idb file in the same folder where exe resides.

B- Importing IDB file to BinNavi
1. In Windows, go to the directory of BinNavi. 
2. Double click on BinNavi.bat. It will open BinNavi GUI
3. In the BinNavi windows, double click on BinNavi1 DB sign (left top sidebar).
4. It will make connection to DB and will unfold the BInNavi1 DB field. 
5. Click on "modules" which lists all the loaded modules in BinNAvi.
6. Right click on "MOdules" and choose "import IDB file". It will open another windows.
7. By traversing "Look in => HOme (symbol)", goto the folder and select the test.idb file and then press ">>" sign. Click import.
8. Once imported, test.exe will appear int he "Module" tree. Double click on this.
8. This will open another window, which has functions defined in the module (lower right pane). By double clicking on any function address, you can open this function graph. this step is not required for our purpose i.e. for API based script. 

9.Just run the provied script as
> jython BOPFunctionRecognition_simple.py
and follow the instructions thereafter.

The output of the script is two files
1. file with results describing the functions that are BOP functions along with loop information (at assembly level)
2. a pickle file that have a list of BOP function.

NOTE:
=====
The provided script is absolutely an unoptimized version and there are many things that can be improved a lot (both code and algorithm wise). We'll be updating it form time to time and also anticipate volunteers to suggest. Please write me mails if you would like to participate or contribute.

Thanks 
Sanjay Rawat
sanjayr@ymail.com 