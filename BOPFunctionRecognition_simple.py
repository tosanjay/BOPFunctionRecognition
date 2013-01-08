
############################################################################
# BOPFunctionRecognition

# Copyright (C) 2012 Sanjay Rawat <sanjayr@ymail.com>
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
#############################################################################
'''

@author:       Sanjay Rawat
@researchers:   Sanjay Rawat and Laurent Mounier
@license:      GNU General Public License 3.0 or later
@contact:      sanjayr@ymail.com;laurent.mounier@imag.fr
@organization: http://www-verimag.imag.fr/
@Citation:  Sanjay Rawat and Laurent Mounier, "Finding Buffer Overflow Inducing Loops in Binary Executables",
In Proc. of the IEEE International Conference on Software Security and Reliability (SERE) 2012, June 2012, Washington DC, USA.
'''
import os
import sys
import gc
import re
##############################################################################################################
## Manual configuration for importing BinNavi module. this should be configured BEFORE running the script ###
### There is one more point in the "main function" where you have to provide your SQL/Post configuration (search for string "connectivity parameter") ####
sys.path.append("drive:\\some\\BinNavi\\BinNavi.jar")
sys.path.append("drive:\\some\\BinNavi\\REIL.jar")
sys.path.append("drive:\\some\\BinNavi\\postgresql-9.0-801.jdbc4.jar")
sys.path.append("drive:\\some\\BinNavi\\guava-r09.jar")
##############################################################################################################
#print sys.path
from javax.swing import JButton, JFrame, JTextArea, JTextField, SwingUtilities, JOptionPane
from java.awt import BorderLayout, Graphics
from java.awt.Window import dispose
from BinNavi.API.plugins import StandAlone
from BinNavi.API.reil.mono import *
from BinNavi.API.helpers import *
from BinNavi.API.helpers.Tree import *
from BinNavi.API.reil.ReilHelpers import *
from BinNavi.API.disassembly.ViewGraphHelpers import *
from BinNavi.API.reil.ReilOperand import *
from BinNavi.API.disassembly.Address import *
from sets import Set
import time
import pickle


def findRoot(nodes):
	"""Finds the root node of a view. Note that this function is a bit imprecise
	   but it should do the trick for most views."""
	for node in nodes:
		if len(node.parents) == 0:
			return node
	return nodes[0]

def getAllParents(start, end, allParents):
    ''' This is the method to get all parents of start node until it reaches end node.'''
    tempStart=start
    
    parents=Set(tempStart.getParents())
    parents.difference_update(allParents)
    allParents.update(Set(parents))

    if len(parents)==0:# or end in parents:
        return allParents
    for pr in parents:
        if pr == end:
            continue

        getAllParents(pr,end, allParents)
    return allParents

def getAllChildren(start, end, allChildren):
    ''' This is the method to get all children of start node until it reaches end node.'''

    tempStart=start
    children=Set(tempStart.getChildren())
    children.difference_update(allChildren)
    allChildren.update(Set(children))
    if len(children) == 0: #or end in children:
        return allChildren
    for ch in children:
        if ch == end:
            continue
        getAllChildren(ch,end, allChildren)
    return allChildren


#Here we create the dominators list.
def fillDominatingSets(currNode, resultDict, currentSet=None ):
    """For each node store a set of dominating nodes in a dictionary,
        thus each set contains the parents of a node. NOTE: this function walks the tree recursively"""
    if currentSet == None:
        currentSet = Set()
    #add itself
    currentSet.add(currNode.getObject().getAddress())
    resultDict[currNode.getObject().getAddress()] = currentSet
    for node in currNode.getChildren():
        newNodeSet = Set()
        #store parent's set in the child one
        newNodeSet.update(currentSet)
        fillDominatingSets(node, resultDict, newNodeSet)

    return resultDict





def findLoops(reilGraph, dominateSet):
''' This function finds all the loops in the given function. It makes use of dominator
algorithm, which is implemented in the BinNavi module.

@param reilGraph: REIL graph of the function
@param dominateSet: dominator set of the function
@ return allLoops; a dictionary of all the loops.

'''
    #print "started findLoops()"
    allLoops={}

    for node in reilGraph.getNodes():
        currAddr = node.getAddress()
        childrenAddr = [child.getAddress() for child in node.getChildren()]
        for address in childrenAddr:
            try:
                dominateSet[currAddr]
                if address in dominateSet[currAddr]:
                    parentSet=Set()
                    childrenSet=Set()
                    parentNode = [n for n in reilGraph.getNodes() if n.getAddress() == currAddr][0]
                    childNode = [n for n in reilGraph.getNodes() if n.getAddress() == address][0]
                    
                    getAllParents(parentNode, childNode, parentSet)
                    parentSet.update((parentNode,childNode))
                    getAllChildren(childNode, parentNode, childrenSet)
                    childrenSet.update((childNode, parentNode))
                    allLoops[(address,parentNode.getAddress())]=Set(parentSet.intersection(childrenSet))
            except KeyError:
                return None

    return allLoops

def getInstNode(address, reilInstGraph):
    ''' Given an address, this function returns the corresponding RIEL instrunction node.'''
    for node in reilInstGraph:
        if node.getInstruction().getAddress()==address:
            return node


def getLastDefinition(instNode,operand, loopAddr):
    ''' Implements a breadth-first search for the last definition of a given operand in an instruction.'''
    store=[] # a queue
    visited=[] # mark the visited nodes
    visited.append(instNode.getInstruction().getAddress()) # initialize the visited node with the first instruction node
    for p in instNode.getParents():
        store.append(p)

    while len(store)>0:
        parent = store.pop(0)
        thisInst=parent.getInstruction()
        if thisInst.getAddress() not in loopAddr or thisInst.getAddress() in visited:
            continue
        if thisInst.thirdOperand.value != '' and thisInst.mnemonic not in ("jcc", "bisz", "stm"):# and thisInst.getAddress() in loopAddr:
            if thisInst.thirdOperand.value == operand:
                #print "$$$ depends on", thisInst
                return parent
        visited.append(thisInst.getAddress())
        for pr in parent.getParents():
            store.append(pr)
    return 0


def getROperands(instruction):
    '''Given a RIEL instruction, this function returns a list of first two operands'''
    oprds=[]
    if isRegister(instruction.getFirstOperand()):
        oprds.append(instruction.firstOperand.value)
    if isRegister(instruction.getSecondOperand()):
        oprds.append(instruction.secondOperand.value)
    return oprds


def getDependencyChain(initOperand, operand, instNode, addrSet, instGraph, chain, repeatedAddr):

    store = []
    repeatedAddr.append(instNode.getInstruction().getAddress())

    nextDefNode1=getLastDefinition(instNode,operand, addrSet)
    if nextDefNode1 == 0:
        return chain
    opsDef=getROperands(nextDefNode1.getInstruction())

    for op in opsDef:
        store.append((op,nextDefNode1.getInstruction().getAddress()))

    while len(store) >0:
        currentOp = store.pop()
        DefInsNode=getInstNode(currentOp[1],instGraph)
        nextDefNode = getLastDefinition(DefInsNode,currentOp[0], addrSet)
        if nextDefNode == 0:
            print "got 0"
            continue
        
        addrDef=nextDefNode.getInstruction().getAddress()
        if addrDef in repeatedAddr:
            continue
        repeatedAddr.append(addrDef)
        
        instruct=nextDefNode.getInstruction()
        
        operandsDef=getROperands(instruct)
        
        chain.extend(operandsDef)
        if 'ebp' in operandsDef or 'esp' in operandsDef or initOperand in operandsDef or addrDef not in addrSet:
            return chain

        for opDef in operandsDef:
            store.append((opDef,addrDef))
            
    return None

def getDependencySrc(operand, instNode, addrSet, instGraph, chain, repeatedAddr):

    store = []
    repeatedAddr.append(instNode.getInstruction().getAddress())

    nextDefNode1=getLastDefinition(instNode,operand, addrSet)
    if nextDefNode1 == 0:
        return chain
    opsDef=getROperands(nextDefNode1.getInstruction())

    for op in opsDef:
        store.append((op,nextDefNode1.getInstruction().getAddress()))

    while len(store) >0:
        currentOp = store.pop()
        DefInsNode=getInstNode(currentOp[1],instGraph)
        nextDefNode = getLastDefinition(DefInsNode,currentOp[0], addrSet)
        if nextDefNode == 0:
            print "got 0"
            continue
        
        addrDef=nextDefNode.getInstruction().getAddress()

        if addrDef in repeatedAddr or addrDef not in addrSet:
            continue
        repeatedAddr.append(addrDef)
        
        instruct=nextDefNode.getInstruction()
        
        operandsDef=getROperands(instruct)
        
        if 'ebp' in operandsDef or 'esp' in operandsDef:
            chain.append(addrDef)
            chain.append(instruct)
            return chain
        
        for opDef in operandsDef:
            store.append((opDef,addrDef))
            
    return None

def isInteresting(loop, instGraph):

    addresses=[]
    stmPresent=False
    for node in loop:
        for ins in node.getInstructions():
            addresses.append(ins.getAddress())

    allSTM=[] # this is the list that containts lists for hash of smt instruction and corresponding inst node.
    for insNode in instGraph:

        if insNode.getInstruction().getAddress() not in addresses:
            continue
        currentInst=insNode.getInstruction()
        if currentInst.getMnemonic() == 'stm':

            if isRegister(currentInst.firstOperand) == False or currentInst.thirdOperand.value == 'esp':
                continue
            #fOp=currentInst.firstOperand.value
            tOp=currentInst.thirdOperand.value
            frOp=currentInst.firstOperand.value
            stmPresent=True
            
            depSMTChain_single=[]
            repeatSMTChain_single=[]
            getDependencyChain(tOp,tOp,insNode, addresses,instGraph, depSMTChain_single, repeatSMTChain_single)

            depSMTChain_single2=[]
            repeatSMTChain_single2=[]
            getDependencyChain(frOp,frOp,insNode, addresses,instGraph, depSMTChain_single2, repeatSMTChain_single2)
            if tOp in depSMTChain_single and frOp in depSMTChain_single2:
                print "pattern B"
                return True

            depSMTChain=[]
            repeatSMTAddr=[]
            getDependencySrc(tOp, insNode, addresses, instGraph, depSMTChain, repeatSMTAddr)
            
            if len(depSMTChain) != 2:
                continue
            fOp=currentInst.firstOperand.value
            tempHashStr=''.join([depSMTChain[1].getMnemonic(),depSMTChain[1].firstOperand.value,depSMTChain[1].secondOperand.value])
            #print hash(tempHashStr)
            allSTM.append([hash(tempHashStr),fOp,insNode])
            stmPresent=True
            

    if stmPresent==False: #this implies that no STM instruction found and therefore loop is not interesting
        return False
    probable=False # this is the boolean to hold the result for source memory changing behavior
    srcSTM=[]
    for stmInd in range(len(allSTM)-1):
        
        noSearch=True
        for stmInd2 in range(stmInd+1,len(allSTM)):
            
            if allSTM[stmInd][0] == allSTM[stmInd2][0]:

                depChain=[]
                repeatedAddr=[]
                
                getDependencyChain(allSTM[stmInd][1],allSTM[stmInd][1],allSTM[stmInd][2], addresses,instGraph, depChain, repeatedAddr)
                if allSTM[stmInd][1] in depChain:
                    print "case 1", allSTM[stmInd][2]
                    probable = True
                    #this means that the other STM i.e. allSTM[stmInd2] is related to actuall memory copy opration.
                    # so, we get the corresponding source in terms of [ebp+src]. Once we get this, a we'll check if
                    # this memory is also changing.
                    depSMTChain=[]
                    repeatSMTAddr=[]
                    getDependencySrc(allSTM[stmInd2][1], allSTM[stmInd2][2], addresses, instGraph, depSMTChain, repeatSMTAddr)
                    if len(depSMTChain) != 2:
                        return False
                    tempHashStr=''.join([depSMTChain[1].getMnemonic(),depSMTChain[1].firstOperand.value,depSMTChain[1].secondOperand.value])
                    
                    srcSTM.extend([hash(tempHashStr)])
                    noSearch=False
                    break
                # we repeat the same self dependency check for the next second STM that is being compared
                depChain=[]
                repeatedAddr=[]
                getDependencyChain(allSTM[stmInd2][1],allSTM[stmInd2][1],allSTM[stmInd2][2], addresses, instGraph, depChain, repeatedAddr)
                if allSTM[stmInd][1] in depChain:
                    print "case 2", allSTM[stmInd2][2]
                    probable= True
                    #this means that the other STM i.e. allSTM[stmInd] is related to actuall memory copy opration.
                    # so, we get the corresponding source in terms of [ebp+src]. Once we get this, a we'll check if
                    # this memory is also changing.
                    depSMTChain=[]
                    repeatSMTAddr=[]
                    getDependencySrc(allSTM[stmInd][1], allSTM[stmInd][2], addresses, instGraph, depSMTChain, repeatSMTAddr)
                    
                    if len(depSMTChain) != 2:
                        return False
                    tempHashStr=''.join([depSMTChain[1].getMnemonic(),depSMTChain[1].firstOperand.value,depSMTChain[1].secondOperand.value])
                    
                    srcSTM.extend([hash(tempHashStr)])
                    noSearch=False
                    break

        if noSearch==False:
            break

    # here we check if the source of the memory copy is also changing
    if probable==True:
        for srcCopy in allSTM:
            if srcCopy[0] == srcSTM[0]:
                depChain=[]
                repeatedAddr=[]
                getDependencyChain(srcCopy[1],srcCopy[1],srcCopy[2], addresses, instGraph, depChain, repeatedAddr)
                if srcCopy[1] in depChain:
                    print "case 3", srcCopy[2]
                    print "pattern A"
                    return True

    return False


def main():
    '''
    Main function that implements main algorithm
    
    '''
    # a file where some log will be created which says how many functions are discovered etc.
    logFile=raw_input("Enter the name of log file")
    # this is provided as an extra file which is a pickled file comtains a list of functions
    # that are found to be BOP. Its main purpose is: if you want to use these functions for some
    # other analysis, just load this file and viola!!!
    fileBOP=raw_input("Enter the file name (full path) to store (Pickled) BOP function's name: ")
    
    interestingFuncs={} # dictionary of interesting functions
    interestingFuncsLOC={} # dictionary of LOC in interesting functions

    binNaviProxy = StandAlone.getPluginInterface()
    
    ################## place to set database connectivity parameter ######### 
    binNaviProxy.databaseManager.addDatabase("","org.postgresql.Driver","localhost","DataBase_name","user","password",False,False)
    ########################################################################
    db=binNaviProxy.databaseManager.databases[0]
    db.connect()
    db.load()
    mods=db.getModules()

    ### initiate dialogBox to setect the module that should be used.

    ######################################################


    frame = JFrame('BinNavi Module Selector',layout=BorderLayout(),
                defaultCloseOperation = JFrame.EXIT_ON_CLOSE,
                size = (500, 500)
            )
    frame2 = JFrame('Function Selector',layout=BorderLayout(),
                defaultCloseOperation = JFrame.EXIT_ON_CLOSE,
                size = (30, 30)
            )


    #convert the module list into the string to be used in the TextBox.
    ## This gives a very ugly box to select the required function (yes, I am bit lazy to learn Java Swing!!). 
    textTemp = map((lambda x,y:"[%d]%s"%(x,y)),range(len(mods)),mods)
    textStr=''.join(textTemp)

    tx=JTextArea(textStr)
    tx.setLineWrap(True);
    tx.setWrapStyleWord(True);
    frame.add(tx,BorderLayout.PAGE_START)
    frame.visible = True
    modInd = JOptionPane.showInputDialog(frame2, "Enter the index of the chosen module",
             "Module selector");

    #Open the module returned by the index
    bfname=mods[int(modInd)] # this modules correxponds to the chosen module
    bfname.load()
    funcViews=bfname.views

    frame2.setVisible(False)
    dispose(frame2)

 ######################################################
    analyzedFunctions = 0
    totalDiscoveredLoops=0
    totalInterestingLoops=0
    time.clock()
    for funcInd in range(1,len(funcViews)):
        
        BBnum=funcViews[funcInd].getNodeCount()
        
        if BBnum <4:
            print "skipped"
            continue #do not analyse function if num of BB less than 4
        
        print 'analyzing %s'%funcViews[funcInd].getName()

        dominatingSets={}#dictionary to keep dominating nodes of a node

        bffunc=bfname.views[int(funcInd)] #this is the view of the buildfname function
        bffunc.load()
        try:
            bfReil=bffunc.getReilCode() # this is the REIL code of the function
        except:
            print "error in getReilCode()"
            bffunc.close()
            gc.collect()
            continue

        bfReilGraph=bfReil.getGraph()
        try:
            #dominatorTree = GraphAlgorithms.getDominatorTree(bfReilGraph, findRoot(bfReilGraph.getNodes())) #only for BinNavi v 3.0
            dominatorTree = GraphAlgorithms.getDominatorTree(bfReilGraph, findRoot(bfReilGraph.getNodes()),None)
        except:
            print "dominator tree problem.. continue with the next function"
            bffunc.close()
            gc.collect()
            continue

        fillDominatingSets(dominatorTree.getRootNode(), dominatingSets, None)

        # let us find loops in this function
        finalLoops=findLoops(bfReilGraph,dominatingSets)
        if finalLoops ==None:
            bffunc.close()
            gc.collect()
            continue
        analyzedFunctions = analyzedFunctions +1
        totalDiscoveredLoops = totalDiscoveredLoops + len(finalLoops)
        # check if the loops are potential candidates for being interesting.
        # this is done by checking if there are atleast 2 STM statements in each loop.
        #print "privious length", len(finalLoops)
        if len(finalLoops)== 0:
            bffunc.close()
            gc.collect()
            continue
        for lp in finalLoops.keys():
            countSTM=0
            for lpn in finalLoops[lp]:
                inst=lpn.getInstructions()
                for i in inst:

                    if i.getMnemonic() == 'stm':
                        countSTM=countSTM+1
                if countSTM >0:
                    break


            if countSTM <= 0:
                del finalLoops[lp]

        #print "latest length", len(finalLoops)

        if len(finalLoops)== 0:
            bffunc.close()
            gc.collect()
            continue


        instGraph = InstructionGraph.create(bfReilGraph)
        
        interestingFuncs[funcViews[funcInd].getName()]=[]
        
        for k in finalLoops.keys():
            print 'analysing loop at %s-%s'%(k[0],k[1])
            if k[0] == k[1]:
                print "skipping this loop as src= dest"
                continue
            #check to skip very big loops i.e. loops having 100 BB
            if len(finalLoops[k]) > 100:
                print "very big loop, skipping!"
                continue
            if isInteresting(finalLoops[k],instGraph) ==True:
                totalInterestingLoops = totalInterestingLoops + 1
                interestingFuncs[funcViews[funcInd].getName()].append(k)
                interestingFuncsLOC[str(funcViews[funcInd].getName())]=sum([len(x.getInstructions()) for x in (getCodeNodes(bffunc.getGraph()))])
                print 'loop at %s IS interesting.'%k[0]
            else:
                print 'loop at %s is NOT interesting.'%k[0]

        #finally close the view of the function
        bffunc.close()
        gc.collect()
        #print bffunc.isLoaded()
        #junky=raw_input("function closed. enter any charater")
    totalTime=time.clock()

# remove the function entries that do not have any interesting loops
    for ky in interestingFuncs.keys():
        if len(interestingFuncs[ky]) == 0:
            del interestingFuncs[ky]

    # write the results in a file
    #


    outFile=open(logFile,'w')
    outFile.write('########## Global Results ###########\n')
    outFile.write('Total Functions in the module: ')
    outFile.write(str(len(funcViews)))
    outFile.write('\nTotal Analyzed Functions in the module: ')
    outFile.write(str(analyzedFunctions))
    outFile.write('\nTotal Interesting Functions in the module: ')
    outFile.write(str(len(interestingFuncs)))
    outFile.write('\nTotal loops discovered in the module: ')
    outFile.write(str(totalDiscoveredLoops))
    outFile.write('\nTotal INTERESTING loops discovered in the module: ')
    outFile.write(str(totalInterestingLoops))
    outFile.write('\nTotal Time: ')
    outFile.write(str(totalTime))
    outFile.write('\n')
    outFile.write('########## Global Results ###########\n')
    for k in interestingFuncs.keys():
        outFile.write("%s: %s: %d"%(str(k), "LOC", interestingFuncsLOC[k]))
        outFile.write('\n')
        for l in interestingFuncs[k]:
            outFile.write('\t')
            outFile.write(str(l))
            outFile.write('\n')
    outFile.close()
    # before we save these BOPS, we include few widely known BOPs which are given int eh following list

    knownBOPs = ['strcpy', 'strncpy', 'memcpy','wcscpy']
    for fn in knownBOPs:
        interestingFuncs[fn] = []


    # save the function name as pickled objects
    fileBOPFd=open(fileBOP+'.pkl', 'w')
    pickle.dump(interestingFuncs.keys(), fileBOPFd)
    fileBOPFd.close()
    print "[*] Pickled in the file %s"%fileBOP+'.pkl'
    print "Done! Closing the module selector window"
    frame.setVisible(False)
    dispose(frame)


if __name__ == '__main__':
    #sys.setrecursionlimit(600000)
    main()
