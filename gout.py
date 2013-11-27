import pygame,sys
from pygame import *
import os
import random

black=(0,0,0)
white=(255,255,255)
red=(255,0,0)
faint=(200,200,150)
brown=(30,30,50)
green=(50,255,50)
blue=(100,100,255)


pygame.init()
yellow=pygame.Color(255,255,25,100)

size=[750,500]
LENGTH=200
HEIGHT=10

screen=pygame.display.set_mode(size)
def draw_screen(screen):
    pygame.display.set_caption("Traffic Analyzer")
    screen.fill(white)

def getNewColor():
	color = [0,0,0]
	color[0] = int(random.getrandbits(8))
	color[1] = int(random.getrandbits(8))
	color[2] = int(random.getrandbits(8))
	return color

def getStats():
	f = open("packet_types.txt","r")
	stats=[]
	for i in range(0,3):
		string=f.readline()
		stats.append(int(string))
	summ=0
	for i in range(0,3):
		summ += stats[i]
	if (summ==0):
		summ=1
	for i in range(0,3):
		stats[i] = (stats[i] * 400)/summ
	f.close();
	return stats

def writeText(caption,num,stats,HEIGHT):
	basicFont = pygame.font.SysFont(None, 15)
	text = basicFont.render(caption, True, black, white)
	textRect = text.get_rect()
	textRect.centery = HEIGHT+BEGINY;
	for i in range(0,num):
		textRect.centerx = textRect.centerx + stats[i]
	textRect.centerx = textRect.centerx + stats[num]/2 + BEGINX
	screen.blit(text,textRect);

def getPacketTypes(BEGINX,BEGINY,HEIGHT):
	stats=getStats();
	basicFont=pygame.font.SysFont(None,30)
	text=basicFont.render("Packet Distribution",True,black,white)
	textRect = text.get_rect()
	textRect.centery = 30
	textRect.centerx = BEGINX + 100
	screen.blit(text,textRect)
	BEGINY += 30
	pygame.draw.rect(screen,red,[BEGINX,BEGINY,stats[0],HEIGHT])
	pygame.draw.rect(screen,green,[BEGINX+stats[0],BEGINY,stats[1],HEIGHT])
	pygame.draw.rect(screen,blue,[BEGINX+stats[0]+stats[1],BEGINY,stats[2],HEIGHT])
	writeText('TCP',0,stats,HEIGHT)
	writeText('UDP',1,stats,HEIGHT)
	writeText('ICMP',2,stats,HEIGHT)
	basicFont=pygame.font.SysFont(None,20)
	text=basicFont.render("TCP -  "+ str(stats[0]/4.0) +"%"+
				",   UDP -  " + str(stats[1]/4.0) + "%" +
				",   ICMP-  " + str(stats[2]/4.0) + "%", True, black, white) 
	textRect = text.get_rect()
	textRect.centery = HEIGHT+BEGINY+25
	textRect.centerx = BEGINX + 200
	screen.blit(text,textRect)

class Histogram():
	def __init__(self,num,filename,xname,yname,name):
		self.num = num
		self.filename=filename
		self.name = name
		self.xname = xname
		self.yname = yname
		self.gap = 10
		self.maxm = num
		self.color = []
		for i in range(0,self.maxm):
			self.color.append(getNewColor())
		self.ip = ["","","","",""]
		self.data = [0,0,0,0,0]
	def readFile(self):
		f=open(self.filename)
		newip=["","","","",""]
		newdata=[0,0,0,0,0]
		updatedSelf=[0,0,0,0,0]
		updatedNew=[0,0,0,0,0]
		for i in range(0,self.maxm):
			string = f.readline()
			(newip[i],newdata[i]) = string.split('\t')
			newdata[i] = (int(newdata[i]))
			if newip[i] in self.ip:
				index = self.ip.index(newip[i])
				self.data[index] = newdata[i]
				updatedSelf[index] = 1
				updatedNew[i] = 1
		j=0
		f.close()
		for i in range(0,self.maxm):
			while updatedSelf[j]==1:
				j+=1
				if (j==self.maxm):
					return
			if updatedNew[i]==1:
				continue
			updatedSelf[j]=1
			updatedNew[i]=1
			self.ip[j] = newip[i]
			self.data[j] = newdata[i]
			self.color[j] = getNewColor()
	def draw(self,posx,posy,height,width):
		pygame.draw.lines(screen,black,False,[(posx,posy+self.gap),(posx,posy-height)],2)
		pygame.draw.lines(screen,black,False,[(posx-self.gap,posy),(posx+width,posy)],2)
		singleWidth = width - (self.maxm+1)*self.gap
		singleWidth /= self.maxm
		gap = self.gap
		totalGap=gap
		maxHeight = height-2*gap
		maxData = max(self.data)
		if (maxData==0):
			maxData=1
		for i in range(0,self.maxm):
			singleHeight = (maxHeight*self.data[i])/maxData
			pygame.draw.rect(screen,self.color[i],[totalGap+posx,posy-singleHeight,singleWidth,singleHeight])

			basicFont=pygame.font.SysFont(None,10)
			text=basicFont.render(self.ip[i],True,black,white)
			textRect = text.get_rect()
			textRect.centery = posy+self.gap
			textRect.centerx = posx + totalGap + singleWidth/2
			screen.blit(text,textRect)

			totalGap += singleWidth + gap

		basicFont=pygame.font.SysFont(None,20)
		text=basicFont.render(self.xname,True,black,white)
		textRect = text.get_rect()
		textRect.centery = posy+ 25
		textRect.centerx = posx + width/2
		screen.blit(text,textRect)

		basicFont=pygame.font.SysFont(None,20)
		text=basicFont.render(self.yname,True,black,white)
		text = pygame.transform.rotate(text,90)
		textRect = text.get_rect()
		textRect.centery = posy - height/2 - self.gap
		textRect.centerx = posx
		screen.blit(text,textRect)

		basicFont=pygame.font.SysFont(None,30)
		text=basicFont.render(self.name,True,black,white)
		textRect = text.get_rect()
		textRect.centery = posy - height - 3*self.gap
		textRect.centerx = posx + width/2 + 35
		screen.blit(text,textRect)
		

clock = pygame.time.Clock()
done=False
(BEGINX,BEGINY) = (20,20)
IP = Histogram(5,'ip_list.txt','IP Address','Usage','Top 5 IP Addresses with Max. Usage')
PacketSize = Histogram(5,'packet_list.txt','Packet Size','Frequency','Packet Size Frequency')
HEIGHT = 50

while done==False:
	draw_screen(screen)
	for event in pygame.event.get():
		if (event.type == pygame.QUIT):
			done = True
	clock.tick(50)
	os.system('./sniffer 1 1')
	getPacketTypes(BEGINX,BEGINY,HEIGHT)
	pygame.draw.lines(screen,black,False,[(0,145),(size[0],145)],3)
	IP.readFile()
	IP.draw(BEGINX,400,200,250)
	pygame.draw.lines(screen,black,False,[(size[0]/2,145),(size[0]/2,size[1])],3)
	PacketSize.readFile()
	PacketSize.draw(BEGINX+400,400,200,250)
	pygame.display.flip()

pygame.quit()
