
./hackme:     file format elf32-i386


Disassembly of section .interp:

08048134 <.interp>:
 8048134:	2f                   	das    
 8048135:	6c                   	insb   (%dx),%es:(%edi)
 8048136:	69 62 2f 6c 64 2d 6c 	imul   $0x6c2d646c,0x2f(%edx),%esp
 804813d:	69 6e 75 78 2e 73 6f 	imul   $0x6f732e78,0x75(%esi),%ebp
 8048144:	2e 32 00             	xor    %cs:(%eax),%al

Disassembly of section .note.ABI-tag:

08048148 <.note.ABI-tag>:
 8048148:	04 00                	add    $0x0,%al
 804814a:	00 00                	add    %al,(%eax)
 804814c:	10 00                	adc    %al,(%eax)
 804814e:	00 00                	add    %al,(%eax)
 8048150:	01 00                	add    %eax,(%eax)
 8048152:	00 00                	add    %al,(%eax)
 8048154:	47                   	inc    %edi
 8048155:	4e                   	dec    %esi
 8048156:	55                   	push   %ebp
 8048157:	00 00                	add    %al,(%eax)
 8048159:	00 00                	add    %al,(%eax)
 804815b:	00 02                	add    %al,(%edx)
 804815d:	00 00                	add    %al,(%eax)
 804815f:	00 06                	add    %al,(%esi)
 8048161:	00 00                	add    %al,(%eax)
 8048163:	00 1b                	add    %bl,(%ebx)
 8048165:	00 00                	add    %al,(%eax)
	...

Disassembly of section .hash:

08048168 <.hash>:
 8048168:	03 00                	add    (%eax),%eax
 804816a:	00 00                	add    %al,(%eax)
 804816c:	08 00                	or     %al,(%eax)
 804816e:	00 00                	add    %al,(%eax)
 8048170:	06                   	push   %es
 8048171:	00 00                	add    %al,(%eax)
 8048173:	00 05 00 00 00 07    	add    %al,0x7000000
	...
 8048185:	00 00                	add    %al,(%eax)
 8048187:	00 02                	add    %al,(%edx)
 8048189:	00 00                	add    %al,(%eax)
 804818b:	00 00                	add    %al,(%eax)
 804818d:	00 00                	add    %al,(%eax)
 804818f:	00 04 00             	add    %al,(%eax,%eax,1)
 8048192:	00 00                	add    %al,(%eax)
 8048194:	03 00                	add    (%eax),%eax
 8048196:	00 00                	add    %al,(%eax)
 8048198:	01 00                	add    %eax,(%eax)
	...

Disassembly of section .gnu.hash:

0804819c <.gnu.hash>:
 804819c:	02 00                	add    (%eax),%al
 804819e:	00 00                	add    %al,(%eax)
 80481a0:	07                   	pop    %es
 80481a1:	00 00                	add    %al,(%eax)
 80481a3:	00 01                	add    %al,(%ecx)
 80481a5:	00 00                	add    %al,(%eax)
 80481a7:	00 05 00 00 00 00    	add    %al,0x0
 80481ad:	20 00                	and    %al,(%eax)
 80481af:	20 00                	and    %al,(%eax)
 80481b1:	00 00                	add    %al,(%eax)
 80481b3:	00 07                	add    %al,(%edi)
 80481b5:	00 00                	add    %al,(%eax)
 80481b7:	00                   	.byte 0x0
 80481b8:	ad                   	lods   %ds:(%esi),%eax
 80481b9:	4b                   	dec    %ebx
 80481ba:	e3 c0                	jecxz  804817c <random@plt-0x214>

Disassembly of section .dynsym:

080481bc <.dynsym>:
	...
 80481cc:	67 00 00             	add    %al,(%bx,%si)
	...
 80481d7:	00 12                	add    %dl,(%edx)
 80481d9:	00 00                	add    %al,(%eax)
 80481db:	00 0c 00             	add    %cl,(%eax,%eax,1)
	...
 80481e6:	00 00                	add    %al,(%eax)
 80481e8:	20 00                	and    %al,(%eax)
 80481ea:	00 00                	add    %al,(%eax)
 80481ec:	1b 00                	sbb    (%eax),%eax
	...
 80481f6:	00 00                	add    %al,(%eax)
 80481f8:	20 00                	and    %al,(%eax)
 80481fa:	00 00                	add    %al,(%eax)
 80481fc:	55                   	push   %ebp
	...
 8048205:	00 00                	add    %al,(%eax)
 8048207:	00 12                	add    %dl,(%edx)
 8048209:	00 00                	add    %al,(%eax)
 804820b:	00 36                	add    %dh,(%esi)
	...
 8048215:	00 00                	add    %al,(%eax)
 8048217:	00 12                	add    %dl,(%edx)
 8048219:	00 00                	add    %al,(%eax)
 804821b:	00 2f                	add    %ch,(%edi)
	...
 8048225:	00 00                	add    %al,(%eax)
 8048227:	00 12                	add    %dl,(%edx)
 8048229:	00 00                	add    %al,(%eax)
 804822b:	00 46 00             	add    %al,0x0(%esi)
 804822e:	00 00                	add    %al,(%eax)
 8048230:	7c 87                	jl     80481b9 <random@plt-0x1d7>
 8048232:	04 08                	add    $0x8,%al
 8048234:	04 00                	add    $0x0,%al
 8048236:	00 00                	add    %al,(%eax)
 8048238:	11 00                	adc    %eax,(%eax)
 804823a:	0f                   	.byte 0xf
	...

Disassembly of section .dynstr:

0804823c <.dynstr>:
 804823c:	00 6c 69 62          	add    %ch,0x62(%ecx,%ebp,2)
 8048240:	64 6c                	fs insb (%dx),%es:(%edi)
 8048242:	2e 73 6f             	jae,pn 80482b4 <random@plt-0xdc>
 8048245:	2e 32 00             	xor    %cs:(%eax),%al
 8048248:	5f                   	pop    %edi
 8048249:	5f                   	pop    %edi
 804824a:	67 6d                	insl   (%dx),%es:(%di)
 804824c:	6f                   	outsl  %ds:(%esi),(%dx)
 804824d:	6e                   	outsb  %ds:(%esi),(%dx)
 804824e:	5f                   	pop    %edi
 804824f:	73 74                	jae    80482c5 <random@plt-0xcb>
 8048251:	61                   	popa   
 8048252:	72 74                	jb     80482c8 <random@plt-0xc8>
 8048254:	5f                   	pop    %edi
 8048255:	5f                   	pop    %edi
 8048256:	00 5f 4a             	add    %bl,0x4a(%edi)
 8048259:	76 5f                	jbe    80482ba <random@plt-0xd6>
 804825b:	52                   	push   %edx
 804825c:	65 67 69 73 74 65 72 	imul   $0x6c437265,%gs:0x74(%bp,%di),%esi
 8048263:	43 6c 
 8048265:	61                   	popa   
 8048266:	73 73                	jae    80482db <random@plt-0xb5>
 8048268:	65 73 00             	gs jae 804826b <random@plt-0x125>
 804826b:	64 6c                	fs insb (%dx),%es:(%edi)
 804826d:	6f                   	outsl  %ds:(%esi),(%dx)
 804826e:	70 65                	jo     80482d5 <random@plt-0xbb>
 8048270:	6e                   	outsb  %ds:(%esi),(%dx)
 8048271:	00 64 6c 73          	add    %ah,0x73(%esp,%ebp,2)
 8048275:	79 6d                	jns    80482e4 <random@plt-0xac>
 8048277:	00 6c 69 62          	add    %ch,0x62(%ecx,%ebp,2)
 804827b:	63 2e                	arpl   %bp,(%esi)
 804827d:	73 6f                	jae    80482ee <random@plt-0xa2>
 804827f:	2e 36 00 5f 49       	cs add %bl,%ss:0x49(%edi)
 8048284:	4f                   	dec    %edi
 8048285:	5f                   	pop    %edi
 8048286:	73 74                	jae    80482fc <random@plt-0x94>
 8048288:	64 69 6e 5f 75 73 65 	imul   $0x64657375,%fs:0x5f(%esi),%ebp
 804828f:	64 
 8048290:	00 5f 5f             	add    %bl,0x5f(%edi)
 8048293:	6c                   	insb   (%dx),%es:(%edi)
 8048294:	69 62 63 5f 73 74 61 	imul   $0x6174735f,0x63(%edx),%esp
 804829b:	72 74                	jb     8048311 <random@plt-0x7f>
 804829d:	5f                   	pop    %edi
 804829e:	6d                   	insl   (%dx),%es:(%edi)
 804829f:	61                   	popa   
 80482a0:	69 6e 00 72 61 6e 64 	imul   $0x646e6172,0x0(%esi),%ebp
 80482a7:	6f                   	outsl  %ds:(%esi),(%dx)
 80482a8:	6d                   	insl   (%dx),%es:(%edi)
 80482a9:	00 47 4c             	add    %al,0x4c(%edi)
 80482ac:	49                   	dec    %ecx
 80482ad:	42                   	inc    %edx
 80482ae:	43                   	inc    %ebx
 80482af:	5f                   	pop    %edi
 80482b0:	32 2e                	xor    (%esi),%ch
 80482b2:	31 00                	xor    %eax,(%eax)
 80482b4:	47                   	inc    %edi
 80482b5:	4c                   	dec    %esp
 80482b6:	49                   	dec    %ecx
 80482b7:	42                   	inc    %edx
 80482b8:	43                   	inc    %ebx
 80482b9:	5f                   	pop    %edi
 80482ba:	32 2e                	xor    (%esi),%ch
 80482bc:	30 00                	xor    %al,(%eax)

Disassembly of section .gnu.version:

080482be <.gnu.version>:
 80482be:	00 00                	add    %al,(%eax)
 80482c0:	02 00                	add    (%eax),%al
 80482c2:	00 00                	add    %al,(%eax)
 80482c4:	00 00                	add    %al,(%eax)
 80482c6:	02 00                	add    (%eax),%al
 80482c8:	03 00                	add    (%eax),%eax
 80482ca:	04 00                	add    $0x0,%al
 80482cc:	01 00                	add    %eax,(%eax)

Disassembly of section .gnu.version_r:

080482d0 <.gnu.version_r>:
 80482d0:	01 00                	add    %eax,(%eax)
 80482d2:	02 00                	add    (%eax),%al
 80482d4:	01 00                	add    %eax,(%eax)
 80482d6:	00 00                	add    %al,(%eax)
 80482d8:	10 00                	adc    %al,(%eax)
 80482da:	00 00                	add    %al,(%eax)
 80482dc:	30 00                	xor    %al,(%eax)
 80482de:	00 00                	add    %al,(%eax)
 80482e0:	11 69 69             	adc    %ebp,0x69(%ecx)
 80482e3:	0d 00 00 04 00       	or     $0x40000,%eax
 80482e8:	6e                   	outsb  %ds:(%esi),(%dx)
 80482e9:	00 00                	add    %al,(%eax)
 80482eb:	00 10                	add    %dl,(%eax)
 80482ed:	00 00                	add    %al,(%eax)
 80482ef:	00 10                	add    %dl,(%eax)
 80482f1:	69 69 0d 00 00 03 00 	imul   $0x30000,0xd(%ecx),%ebp
 80482f8:	78 00                	js     80482fa <random@plt-0x96>
 80482fa:	00 00                	add    %al,(%eax)
 80482fc:	00 00                	add    %al,(%eax)
 80482fe:	00 00                	add    %al,(%eax)
 8048300:	01 00                	add    %eax,(%eax)
 8048302:	01 00                	add    %eax,(%eax)
 8048304:	3c 00                	cmp    $0x0,%al
 8048306:	00 00                	add    %al,(%eax)
 8048308:	10 00                	adc    %al,(%eax)
 804830a:	00 00                	add    %al,(%eax)
 804830c:	00 00                	add    %al,(%eax)
 804830e:	00 00                	add    %al,(%eax)
 8048310:	10 69 69             	adc    %ch,0x69(%ecx)
 8048313:	0d 00 00 02 00       	or     $0x20000,%eax
 8048318:	78 00                	js     804831a <random@plt-0x76>
 804831a:	00 00                	add    %al,(%eax)
 804831c:	00 00                	add    %al,(%eax)
	...

Disassembly of section .rel.dyn:

08048320 <.rel.dyn>:
 8048320:	5c                   	pop    %esp
 8048321:	99                   	cltd   
 8048322:	04 08                	add    $0x8,%al
 8048324:	06                   	push   %es
 8048325:	02 00                	add    (%eax),%al
	...

Disassembly of section .rel.plt:

08048328 <.rel.plt>:
 8048328:	6c                   	insb   (%dx),%es:(%edi)
 8048329:	99                   	cltd   
 804832a:	04 08                	add    $0x8,%al
 804832c:	07                   	pop    %es
 804832d:	01 00                	add    %eax,(%eax)
 804832f:	00 70 99             	add    %dh,-0x67(%eax)
 8048332:	04 08                	add    $0x8,%al
 8048334:	07                   	pop    %es
 8048335:	02 00                	add    (%eax),%al
 8048337:	00 74 99 04          	add    %dh,0x4(%ecx,%ebx,4)
 804833b:	08 07                	or     %al,(%edi)
 804833d:	04 00                	add    $0x0,%al
 804833f:	00 78 99             	add    %bh,-0x67(%eax)
 8048342:	04 08                	add    $0x8,%al
 8048344:	07                   	pop    %es
 8048345:	05 00 00 7c 99       	add    $0x997c0000,%eax
 804834a:	04 08                	add    $0x8,%al
 804834c:	07                   	pop    %es
 804834d:	06                   	push   %es
	...

Disassembly of section .init:

08048350 <.init>:
 8048350:	53                   	push   %ebx
 8048351:	83 ec 08             	sub    $0x8,%esp
 8048354:	e8 00 00 00 00       	call   8048359 <random@plt-0x37>
 8048359:	5b                   	pop    %ebx
 804835a:	81 c3 07 16 00 00    	add    $0x1607,%ebx
 8048360:	8b 83 fc ff ff ff    	mov    -0x4(%ebx),%eax
 8048366:	85 c0                	test   %eax,%eax
 8048368:	74 05                	je     804836f <random@plt-0x21>
 804836a:	e8 31 00 00 00       	call   80483a0 <__gmon_start__@plt>
 804836f:	e8 fc 00 00 00       	call   8048470 <dlopen@plt+0xa0>
 8048374:	e8 b7 03 00 00       	call   8048730 <dlopen@plt+0x360>
 8048379:	83 c4 08             	add    $0x8,%esp
 804837c:	5b                   	pop    %ebx
 804837d:	c3                   	ret    

Disassembly of section .plt:

08048380 <random@plt-0x10>:
 8048380:	ff 35 64 99 04 08    	pushl  0x8049964
 8048386:	ff 25 68 99 04 08    	jmp    *0x8049968
 804838c:	00 00                	add    %al,(%eax)
	...

08048390 <random@plt>:
 8048390:	ff 25 6c 99 04 08    	jmp    *0x804996c
 8048396:	68 00 00 00 00       	push   $0x0
 804839b:	e9 e0 ff ff ff       	jmp    8048380 <random@plt-0x10>

080483a0 <__gmon_start__@plt>:
 80483a0:	ff 25 70 99 04 08    	jmp    *0x8049970
 80483a6:	68 08 00 00 00       	push   $0x8
 80483ab:	e9 d0 ff ff ff       	jmp    8048380 <random@plt-0x10>

080483b0 <__libc_start_main@plt>:
 80483b0:	ff 25 74 99 04 08    	jmp    *0x8049974
 80483b6:	68 10 00 00 00       	push   $0x10
 80483bb:	e9 c0 ff ff ff       	jmp    8048380 <random@plt-0x10>

080483c0 <dlsym@plt>:
 80483c0:	ff 25 78 99 04 08    	jmp    *0x8049978
 80483c6:	68 18 00 00 00       	push   $0x18
 80483cb:	e9 b0 ff ff ff       	jmp    8048380 <random@plt-0x10>

080483d0 <dlopen@plt>:
 80483d0:	ff 25 7c 99 04 08    	jmp    *0x804997c
 80483d6:	68 20 00 00 00       	push   $0x20
 80483db:	e9 a0 ff ff ff       	jmp    8048380 <random@plt-0x10>

Disassembly of section .text:

080483e0 <.text>:
 80483e0:	31 ed                	xor    %ebp,%ebp
 80483e2:	5e                   	pop    %esi
 80483e3:	89 e1                	mov    %esp,%ecx
 80483e5:	83 e4 f0             	and    $0xfffffff0,%esp
 80483e8:	50                   	push   %eax
 80483e9:	54                   	push   %esp
 80483ea:	52                   	push   %edx
 80483eb:	68 20 87 04 08       	push   $0x8048720
 80483f0:	68 b0 86 04 08       	push   $0x80486b0
 80483f5:	51                   	push   %ecx
 80483f6:	56                   	push   %esi
 80483f7:	68 45 86 04 08       	push   $0x8048645
 80483fc:	e8 af ff ff ff       	call   80483b0 <__libc_start_main@plt>
 8048401:	f4                   	hlt    
 8048402:	90                   	nop
 8048403:	90                   	nop
 8048404:	90                   	nop
 8048405:	90                   	nop
 8048406:	90                   	nop
 8048407:	90                   	nop
 8048408:	90                   	nop
 8048409:	90                   	nop
 804840a:	90                   	nop
 804840b:	90                   	nop
 804840c:	90                   	nop
 804840d:	90                   	nop
 804840e:	90                   	nop
 804840f:	90                   	nop
 8048410:	55                   	push   %ebp
 8048411:	89 e5                	mov    %esp,%ebp
 8048413:	53                   	push   %ebx
 8048414:	83 ec 04             	sub    $0x4,%esp
 8048417:	80 3d 88 99 04 08 00 	cmpb   $0x0,0x8049988
 804841e:	75 3f                	jne    804845f <dlopen@plt+0x8f>
 8048420:	a1 8c 99 04 08       	mov    0x804998c,%eax
 8048425:	bb 7c 98 04 08       	mov    $0x804987c,%ebx
 804842a:	81 eb 78 98 04 08    	sub    $0x8049878,%ebx
 8048430:	c1 fb 02             	sar    $0x2,%ebx
 8048433:	83 eb 01             	sub    $0x1,%ebx
 8048436:	39 d8                	cmp    %ebx,%eax
 8048438:	73 1e                	jae    8048458 <dlopen@plt+0x88>
 804843a:	8d b6 00 00 00 00    	lea    0x0(%esi),%esi
 8048440:	83 c0 01             	add    $0x1,%eax
 8048443:	a3 8c 99 04 08       	mov    %eax,0x804998c
 8048448:	ff 14 85 78 98 04 08 	call   *0x8049878(,%eax,4)
 804844f:	a1 8c 99 04 08       	mov    0x804998c,%eax
 8048454:	39 d8                	cmp    %ebx,%eax
 8048456:	72 e8                	jb     8048440 <dlopen@plt+0x70>
 8048458:	c6 05 88 99 04 08 01 	movb   $0x1,0x8049988
 804845f:	83 c4 04             	add    $0x4,%esp
 8048462:	5b                   	pop    %ebx
 8048463:	5d                   	pop    %ebp
 8048464:	c3                   	ret    
 8048465:	8d 74 26 00          	lea    0x0(%esi,%eiz,1),%esi
 8048469:	8d bc 27 00 00 00 00 	lea    0x0(%edi,%eiz,1),%edi
 8048470:	55                   	push   %ebp
 8048471:	89 e5                	mov    %esp,%ebp
 8048473:	83 ec 18             	sub    $0x18,%esp
 8048476:	a1 80 98 04 08       	mov    0x8049880,%eax
 804847b:	85 c0                	test   %eax,%eax
 804847d:	74 12                	je     8048491 <dlopen@plt+0xc1>
 804847f:	b8 00 00 00 00       	mov    $0x0,%eax
 8048484:	85 c0                	test   %eax,%eax
 8048486:	74 09                	je     8048491 <dlopen@plt+0xc1>
 8048488:	c7 04 24 80 98 04 08 	movl   $0x8049880,(%esp)
 804848f:	ff d0                	call   *%eax
 8048491:	c9                   	leave  
 8048492:	c3                   	ret    
 8048493:	90                   	nop
 8048494:	55                   	push   %ebp
 8048495:	31 c0                	xor    %eax,%eax
 8048497:	89 e5                	mov    %esp,%ebp
 8048499:	81 ec 88 00 00 00    	sub    $0x88,%esp
 804849f:	8b 4d 08             	mov    0x8(%ebp),%ecx
 80484a2:	eb 0b                	jmp    80484af <dlopen@plt+0xdf>
 80484a4:	83 f2 aa             	xor    $0xffffffaa,%edx
 80484a7:	88 94 05 78 ff ff ff 	mov    %dl,-0x88(%ebp,%eax,1)
 80484ae:	40                   	inc    %eax
 80484af:	8a 14 01             	mov    (%ecx,%eax,1),%dl
 80484b2:	84 d2                	test   %dl,%dl
 80484b4:	75 ee                	jne    80484a4 <dlopen@plt+0xd4>
 80484b6:	c6 84 05 78 ff ff ff 	movb   $0x0,-0x88(%ebp,%eax,1)
 80484bd:	00 
 80484be:	50                   	push   %eax
 80484bf:	50                   	push   %eax
 80484c0:	6a 02                	push   $0x2
 80484c2:	8d 85 78 ff ff ff    	lea    -0x88(%ebp),%eax
 80484c8:	50                   	push   %eax
 80484c9:	e8 02 ff ff ff       	call   80483d0 <dlopen@plt>
 80484ce:	c9                   	leave  
 80484cf:	c3                   	ret    
 80484d0:	55                   	push   %ebp
 80484d1:	31 c0                	xor    %eax,%eax
 80484d3:	89 e5                	mov    %esp,%ebp
 80484d5:	81 ec 88 00 00 00    	sub    $0x88,%esp
 80484db:	8b 4d 0c             	mov    0xc(%ebp),%ecx
 80484de:	eb 0b                	jmp    80484eb <dlopen@plt+0x11b>
 80484e0:	83 f2 55             	xor    $0x55,%edx
 80484e3:	88 94 05 78 ff ff ff 	mov    %dl,-0x88(%ebp,%eax,1)
 80484ea:	40                   	inc    %eax
 80484eb:	8a 14 01             	mov    (%ecx,%eax,1),%dl
 80484ee:	84 d2                	test   %dl,%dl
 80484f0:	75 ee                	jne    80484e0 <dlopen@plt+0x110>
 80484f2:	52                   	push   %edx
 80484f3:	52                   	push   %edx
 80484f4:	c6 84 05 78 ff ff ff 	movb   $0x0,-0x88(%ebp,%eax,1)
 80484fb:	00 
 80484fc:	8d 85 78 ff ff ff    	lea    -0x88(%ebp),%eax
 8048502:	50                   	push   %eax
 8048503:	ff 75 08             	pushl  0x8(%ebp)
 8048506:	e8 b5 fe ff ff       	call   80483c0 <dlsym@plt>
 804850b:	c9                   	leave  
 804850c:	c3                   	ret    
 804850d:	55                   	push   %ebp
 804850e:	89 e5                	mov    %esp,%ebp
 8048510:	83 ec 14             	sub    $0x14,%esp
 8048513:	68 68 86 04 08       	push   $0x8048668
 8048518:	e8 77 ff ff ff       	call   8048494 <dlopen@plt+0xc4>
 804851d:	5a                   	pop    %edx
 804851e:	59                   	pop    %ecx
 804851f:	68 84 86 04 08       	push   $0x8048684
 8048524:	50                   	push   %eax
 8048525:	a3 a0 99 04 08       	mov    %eax,0x80499a0
 804852a:	e8 a1 ff ff ff       	call   80484d0 <dlopen@plt+0x100>
 804852f:	5a                   	pop    %edx
 8048530:	59                   	pop    %ecx
 8048531:	68 8c 86 04 08       	push   $0x804868c
 8048536:	ff 35 a0 99 04 08    	pushl  0x80499a0
 804853c:	a3 98 99 04 08       	mov    %eax,0x8049998
 8048541:	e8 8a ff ff ff       	call   80484d0 <dlopen@plt+0x100>
 8048546:	59                   	pop    %ecx
 8048547:	a3 90 99 04 08       	mov    %eax,0x8049990
 804854c:	58                   	pop    %eax
 804854d:	68 94 86 04 08       	push   $0x8048694
 8048552:	ff 35 a0 99 04 08    	pushl  0x80499a0
 8048558:	e8 73 ff ff ff       	call   80484d0 <dlopen@plt+0x100>
 804855d:	6a 00                	push   $0x0
 804855f:	6a 00                	push   $0x0
 8048561:	6a 00                	push   $0x0
 8048563:	6a 00                	push   $0x0
 8048565:	a3 94 99 04 08       	mov    %eax,0x8049994
 804856a:	ff 15 98 99 04 08    	call   *0x8049998
 8048570:	83 c4 20             	add    $0x20,%esp
 8048573:	85 c0                	test   %eax,%eax
 8048575:	79 18                	jns    804858f <dlopen@plt+0x1bf>
 8048577:	83 ec 0c             	sub    $0xc,%esp
 804857a:	68 80 87 04 08       	push   $0x8048780
 804857f:	ff 15 94 99 04 08    	call   *0x8049994
 8048585:	b8 01 00 00 00       	mov    $0x1,%eax
 804858a:	cd 80                	int    $0x80
 804858c:	83 c4 10             	add    $0x10,%esp
 804858f:	c9                   	leave  
 8048590:	c3                   	ret    
 8048591:	55                   	push   %ebp
 8048592:	89 e5                	mov    %esp,%ebp
 8048594:	57                   	push   %edi
 8048595:	56                   	push   %esi
 8048596:	53                   	push   %ebx
 8048597:	81 ec 98 00 00 00    	sub    $0x98,%esp
 804859d:	68 99 87 04 08       	push   $0x8048799
 80485a2:	ff 15 94 99 04 08    	call   *0x8049994
 80485a8:	8d 45 84             	lea    -0x7c(%ebp),%eax
 80485ab:	5b                   	pop    %ebx
 80485ac:	5e                   	pop    %esi
 80485ad:	50                   	push   %eax
 80485ae:	68 ac 87 04 08       	push   $0x80487ac
 80485b3:	ff 15 90 99 04 08    	call   *0x8049990
 80485b9:	83 c4 10             	add    $0x10,%esp
 80485bc:	31 c0                	xor    %eax,%eax
 80485be:	eb 01                	jmp    80485c1 <dlopen@plt+0x1f1>
 80485c0:	40                   	inc    %eax
 80485c1:	80 7c 05 84 00       	cmpb   $0x0,-0x7c(%ebp,%eax,1)
 80485c6:	75 f8                	jne    80485c0 <dlopen@plt+0x1f0>
 80485c8:	31 db                	xor    %ebx,%ebx
 80485ca:	83 f8 13             	cmp    $0x13,%eax
 80485cd:	0f 94 c3             	sete   %bl
 80485d0:	be 0a 00 00 00       	mov    $0xa,%esi
 80485d5:	e8 b6 fd ff ff       	call   8048390 <random@plt>
 80485da:	b9 13 00 00 00       	mov    $0x13,%ecx
 80485df:	99                   	cltd   
 80485e0:	f7 f9                	idiv   %ecx
 80485e2:	31 c0                	xor    %eax,%eax
 80485e4:	8a 8a 9c 86 04 08    	mov    0x804869c(%edx),%cl
 80485ea:	0f b6 7c 15 84       	movzbl -0x7c(%ebp,%edx,1),%edi
 80485ef:	42                   	inc    %edx
 80485f0:	89 95 74 ff ff ff    	mov    %edx,-0x8c(%ebp)
 80485f6:	31 d2                	xor    %edx,%edx
 80485f8:	eb 0c                	jmp    8048606 <dlopen@plt+0x236>
 80485fa:	69 c0 8d 78 01 6d    	imul   $0x6d01788d,%eax,%eax
 8048600:	42                   	inc    %edx
 8048601:	05 39 30 00 00       	add    $0x3039,%eax
 8048606:	3b 95 74 ff ff ff    	cmp    -0x8c(%ebp),%edx
 804860c:	7c ec                	jl     80485fa <dlopen@plt+0x22a>
 804860e:	31 f8                	xor    %edi,%eax
 8048610:	38 c1                	cmp    %al,%cl
 8048612:	b8 00 00 00 00       	mov    $0x0,%eax
 8048617:	0f 45 d8             	cmovne %eax,%ebx
 804861a:	4e                   	dec    %esi
 804861b:	75 b8                	jne    80485d5 <dlopen@plt+0x205>
 804861d:	85 db                	test   %ebx,%ebx
 804861f:	a1 94 99 04 08       	mov    0x8049994,%eax
 8048624:	74 0a                	je     8048630 <dlopen@plt+0x260>
 8048626:	83 ec 0c             	sub    $0xc,%esp
 8048629:	68 af 87 04 08       	push   $0x80487af
 804862e:	eb 08                	jmp    8048638 <dlopen@plt+0x268>
 8048630:	83 ec 0c             	sub    $0xc,%esp
 8048633:	68 c1 87 04 08       	push   $0x80487c1
 8048638:	ff d0                	call   *%eax
 804863a:	83 c4 10             	add    $0x10,%esp
 804863d:	8d 65 f4             	lea    -0xc(%ebp),%esp
 8048640:	5b                   	pop    %ebx
 8048641:	5e                   	pop    %esi
 8048642:	5f                   	pop    %edi
 8048643:	5d                   	pop    %ebp
 8048644:	c3                   	ret    
 8048645:	8d 4c 24 04          	lea    0x4(%esp),%ecx
 8048649:	83 e4 f0             	and    $0xfffffff0,%esp
 804864c:	ff 71 fc             	pushl  -0x4(%ecx)
 804864f:	55                   	push   %ebp
 8048650:	89 e5                	mov    %esp,%ebp
 8048652:	51                   	push   %ecx
 8048653:	83 ec 04             	sub    $0x4,%esp
 8048656:	e8 b2 fe ff ff       	call   804850d <dlopen@plt+0x13d>
 804865b:	e8 31 ff ff ff       	call   8048591 <dlopen@plt+0x1c1>
 8048660:	5a                   	pop    %edx
 8048661:	59                   	pop    %ecx
 8048662:	5d                   	pop    %ebp
 8048663:	8d 61 fc             	lea    -0x4(%ecx),%esp
 8048666:	c3                   	ret    
 8048667:	90                   	nop
 8048668:	85 c6                	test   %eax,%esi
 804866a:	c3                   	ret    
 804866b:	c8 85 c6 c3          	enter  $0xc685,$0xc3
 804866f:	c8 c9 84 d9          	enter  $0x84c9,$0xd9
 8048673:	c5 84 9c 00 90 38 25 	lds    0x25389000(%esp,%ebx,4),%eax
 804867a:	27                   	daa    
 804867b:	3a 21                	cmp    (%ecx),%ah
 804867d:	30 36                	xor    %dh,(%esi)
 804867f:	21 00                	and    %eax,(%eax)
 8048681:	8d 76 00             	lea    0x0(%esi),%esi
 8048684:	25 21 27 34 36       	and    $0x36342721,%eax
 8048689:	30 00                	xor    %al,(%eax)
 804868b:	90                   	nop
 804868c:	26 36 34 3b          	es ss xor $0x3b,%al
 8048690:	33 00                	xor    (%eax),%eax
 8048692:	66 90                	xchg   %ax,%ax
 8048694:	25 27 3c 3b 21       	and    $0x213b3c27,%eax
 8048699:	33 00                	xor    (%eax),%eax
 804869b:	90                   	nop
 804869c:	6a fb                	push   $0xfffffffb
 804869e:	4c                   	dec    %esp
 804869f:	8d 58 0f             	lea    0xf(%eax),%ebx
 80486a2:	d4 e8                	aam    $0xe8
 80486a4:	94                   	xchg   %eax,%esp
 80486a5:	98                   	cwtl   
 80486a6:	ee                   	out    %al,(%dx)
 80486a7:	6b 18 30             	imul   $0x30,(%eax),%ebx
 80486aa:	e0 55                	loopne 8048701 <dlopen@plt+0x331>
 80486ac:	c5 28                	lds    (%eax),%ebp
 80486ae:	0e                   	push   %cs
 80486af:	90                   	nop
 80486b0:	55                   	push   %ebp
 80486b1:	57                   	push   %edi
 80486b2:	56                   	push   %esi
 80486b3:	53                   	push   %ebx
 80486b4:	e8 69 00 00 00       	call   8048722 <dlopen@plt+0x352>
 80486b9:	81 c3 a7 12 00 00    	add    $0x12a7,%ebx
 80486bf:	83 ec 1c             	sub    $0x1c,%esp
 80486c2:	8b 6c 24 30          	mov    0x30(%esp),%ebp
 80486c6:	8d bb 10 ff ff ff    	lea    -0xf0(%ebx),%edi
 80486cc:	e8 7f fc ff ff       	call   8048350 <random@plt-0x40>
 80486d1:	8d 83 10 ff ff ff    	lea    -0xf0(%ebx),%eax
 80486d7:	29 c7                	sub    %eax,%edi
 80486d9:	c1 ff 02             	sar    $0x2,%edi
 80486dc:	85 ff                	test   %edi,%edi
 80486de:	74 29                	je     8048709 <dlopen@plt+0x339>
 80486e0:	31 f6                	xor    %esi,%esi
 80486e2:	8d b6 00 00 00 00    	lea    0x0(%esi),%esi
 80486e8:	8b 44 24 38          	mov    0x38(%esp),%eax
 80486ec:	89 2c 24             	mov    %ebp,(%esp)
 80486ef:	89 44 24 08          	mov    %eax,0x8(%esp)
 80486f3:	8b 44 24 34          	mov    0x34(%esp),%eax
 80486f7:	89 44 24 04          	mov    %eax,0x4(%esp)
 80486fb:	ff 94 b3 10 ff ff ff 	call   *-0xf0(%ebx,%esi,4)
 8048702:	83 c6 01             	add    $0x1,%esi
 8048705:	39 fe                	cmp    %edi,%esi
 8048707:	75 df                	jne    80486e8 <dlopen@plt+0x318>
 8048709:	83 c4 1c             	add    $0x1c,%esp
 804870c:	5b                   	pop    %ebx
 804870d:	5e                   	pop    %esi
 804870e:	5f                   	pop    %edi
 804870f:	5d                   	pop    %ebp
 8048710:	c3                   	ret    
 8048711:	eb 0d                	jmp    8048720 <dlopen@plt+0x350>
 8048713:	90                   	nop
 8048714:	90                   	nop
 8048715:	90                   	nop
 8048716:	90                   	nop
 8048717:	90                   	nop
 8048718:	90                   	nop
 8048719:	90                   	nop
 804871a:	90                   	nop
 804871b:	90                   	nop
 804871c:	90                   	nop
 804871d:	90                   	nop
 804871e:	90                   	nop
 804871f:	90                   	nop
 8048720:	f3 c3                	repz ret 
 8048722:	8b 1c 24             	mov    (%esp),%ebx
 8048725:	c3                   	ret    
 8048726:	90                   	nop
 8048727:	90                   	nop
 8048728:	90                   	nop
 8048729:	90                   	nop
 804872a:	90                   	nop
 804872b:	90                   	nop
 804872c:	90                   	nop
 804872d:	90                   	nop
 804872e:	90                   	nop
 804872f:	90                   	nop
 8048730:	55                   	push   %ebp
 8048731:	89 e5                	mov    %esp,%ebp
 8048733:	53                   	push   %ebx
 8048734:	83 ec 04             	sub    $0x4,%esp
 8048737:	a1 70 98 04 08       	mov    0x8049870,%eax
 804873c:	83 f8 ff             	cmp    $0xffffffff,%eax
 804873f:	74 13                	je     8048754 <dlopen@plt+0x384>
 8048741:	bb 70 98 04 08       	mov    $0x8049870,%ebx
 8048746:	66 90                	xchg   %ax,%ax
 8048748:	83 eb 04             	sub    $0x4,%ebx
 804874b:	ff d0                	call   *%eax
 804874d:	8b 03                	mov    (%ebx),%eax
 804874f:	83 f8 ff             	cmp    $0xffffffff,%eax
 8048752:	75 f4                	jne    8048748 <dlopen@plt+0x378>
 8048754:	83 c4 04             	add    $0x4,%esp
 8048757:	5b                   	pop    %ebx
 8048758:	5d                   	pop    %ebp
 8048759:	c3                   	ret    
 804875a:	90                   	nop
 804875b:	90                   	nop

Disassembly of section .fini:

0804875c <.fini>:
 804875c:	53                   	push   %ebx
 804875d:	83 ec 08             	sub    $0x8,%esp
 8048760:	e8 00 00 00 00       	call   8048765 <dlopen@plt+0x395>
 8048765:	5b                   	pop    %ebx
 8048766:	81 c3 fb 11 00 00    	add    $0x11fb,%ebx
 804876c:	e8 9f fc ff ff       	call   8048410 <dlopen@plt+0x40>
 8048771:	83 c4 08             	add    $0x8,%esp
 8048774:	5b                   	pop    %ebx
 8048775:	c3                   	ret    

Disassembly of section .rodata:

08048778 <_IO_stdin_used@@Base-0x4>:
 8048778:	03 00                	add    (%eax),%eax
	...

0804877c <_IO_stdin_used@@Base>:
 804877c:	01 00                	add    %eax,(%eax)
 804877e:	02 00                	add    (%eax),%al
 8048780:	46                   	inc    %esi
 8048781:	75 63                	jne    80487e6 <_IO_stdin_used@@Base+0x6a>
 8048783:	6b 20 6f             	imul   $0x6f,(%eax),%esp
 8048786:	66 66 21 20          	data16 and %sp,(%eax)
 804878a:	6e                   	outsb  %ds:(%esi),(%dx)
 804878b:	6f                   	outsl  %ds:(%esi),(%dx)
 804878c:	20 64 65 62          	and    %ah,0x62(%ebp,%eiz,2)
 8048790:	75 67                	jne    80487f9 <_IO_stdin_used@@Base+0x7d>
 8048792:	67 65 72 73          	addr16 gs jb 8048809 <_IO_stdin_used@@Base+0x8d>
 8048796:	21 0a                	and    %ecx,(%edx)
 8048798:	00 50 61             	add    %dl,0x61(%eax)
 804879b:	73 73                	jae    8048810 <_IO_stdin_used@@Base+0x94>
 804879d:	77 6f                	ja     804880e <_IO_stdin_used@@Base+0x92>
 804879f:	72 64                	jb     8048805 <_IO_stdin_used@@Base+0x89>
 80487a1:	2c 20                	sub    $0x20,%al
 80487a3:	70 6c                	jo     8048811 <_IO_stdin_used@@Base+0x95>
 80487a5:	65 61                	gs popa 
 80487a7:	73 65                	jae    804880e <_IO_stdin_used@@Base+0x92>
 80487a9:	3f                   	aas    
 80487aa:	20 00                	and    %al,(%eax)
 80487ac:	25 73 00 43 6f       	and    $0x6f430073,%eax
 80487b1:	6e                   	outsb  %ds:(%esi),(%dx)
 80487b2:	67 72 61             	addr16 jb 8048816 <_IO_stdin_used@@Base+0x9a>
 80487b5:	74 75                	je     804882c <_IO_stdin_used@@Base+0xb0>
 80487b7:	6c                   	insb   (%dx),%es:(%edi)
 80487b8:	61                   	popa   
 80487b9:	74 69                	je     8048824 <_IO_stdin_used@@Base+0xa8>
 80487bb:	6f                   	outsl  %ds:(%esi),(%dx)
 80487bc:	6e                   	outsb  %ds:(%esi),(%dx)
 80487bd:	73 21                	jae    80487e0 <_IO_stdin_used@@Base+0x64>
 80487bf:	0a 00                	or     (%eax),%al
 80487c1:	4f                   	dec    %edi
 80487c2:	6f                   	outsl  %ds:(%esi),(%dx)
 80487c3:	70 73                	jo     8048838 <_IO_stdin_used@@Base+0xbc>
 80487c5:	2e 2e 0a 00          	cs or  %cs:(%eax),%al

Disassembly of section .eh_frame_hdr:

080487cc <.eh_frame_hdr>:
 80487cc:	01 1b                	add    %ebx,(%ebx)
 80487ce:	03 3b                	add    (%ebx),%edi
 80487d0:	20 00                	and    %al,(%eax)
 80487d2:	00 00                	add    %al,(%eax)
 80487d4:	03 00                	add    (%eax),%eax
 80487d6:	00 00                	add    %al,(%eax)
 80487d8:	e4 fe                	in     $0xfe,%al
 80487da:	ff                   	(bad)  
 80487db:	ff                   	(bad)  
 80487dc:	3c 00                	cmp    $0x0,%al
 80487de:	00 00                	add    %al,(%eax)
 80487e0:	54                   	push   %esp
 80487e1:	ff                   	(bad)  
 80487e2:	ff                   	(bad)  
 80487e3:	ff                   	(bad)  
 80487e4:	78 00                	js     80487e6 <_IO_stdin_used@@Base+0x6a>
 80487e6:	00 00                	add    %al,(%eax)
 80487e8:	56                   	push   %esi
 80487e9:	ff                   	(bad)  
 80487ea:	ff                   	(bad)  
 80487eb:	ff                   	.byte 0xff
 80487ec:	8c 00                	mov    %es,(%eax)
	...

Disassembly of section .eh_frame:

080487f0 <.eh_frame>:
 80487f0:	14 00                	adc    $0x0,%al
 80487f2:	00 00                	add    %al,(%eax)
 80487f4:	00 00                	add    %al,(%eax)
 80487f6:	00 00                	add    %al,(%eax)
 80487f8:	01 7a 52             	add    %edi,0x52(%edx)
 80487fb:	00 01                	add    %al,(%ecx)
 80487fd:	7c 08                	jl     8048807 <_IO_stdin_used@@Base+0x8b>
 80487ff:	01 1b                	add    %ebx,(%ebx)
 8048801:	0c 04                	or     $0x4,%al
 8048803:	04 88                	add    $0x88,%al
 8048805:	01 00                	add    %eax,(%eax)
 8048807:	00 38                	add    %bh,(%eax)
 8048809:	00 00                	add    %al,(%eax)
 804880b:	00 1c 00             	add    %bl,(%eax,%eax,1)
 804880e:	00 00                	add    %al,(%eax)
 8048810:	a0 fe ff ff 61       	mov    0x61fffffe,%al
 8048815:	00 00                	add    %al,(%eax)
 8048817:	00 00                	add    %al,(%eax)
 8048819:	41                   	inc    %ecx
 804881a:	0e                   	push   %cs
 804881b:	08 85 02 41 0e 0c    	or     %al,0xc0e4102(%ebp)
 8048821:	87 03                	xchg   %eax,(%ebx)
 8048823:	41                   	inc    %ecx
 8048824:	0e                   	push   %cs
 8048825:	10 86 04 41 0e 14    	adc    %al,0x140e4104(%esi)
 804882b:	83 05 4e 0e 30 02 4a 	addl   $0x4a,0x2300e4e
 8048832:	0e                   	push   %cs
 8048833:	14 41                	adc    $0x41,%al
 8048835:	0e                   	push   %cs
 8048836:	10 c3                	adc    %al,%bl
 8048838:	41                   	inc    %ecx
 8048839:	0e                   	push   %cs
 804883a:	0c c6                	or     $0xc6,%al
 804883c:	41                   	inc    %ecx
 804883d:	0e                   	push   %cs
 804883e:	08 c7                	or     %al,%bh
 8048840:	41                   	inc    %ecx
 8048841:	0e                   	push   %cs
 8048842:	04 c5                	add    $0xc5,%al
 8048844:	10 00                	adc    %al,(%eax)
 8048846:	00 00                	add    %al,(%eax)
 8048848:	58                   	pop    %eax
 8048849:	00 00                	add    %al,(%eax)
 804884b:	00 d4                	add    %dl,%ah
 804884d:	fe                   	(bad)  
 804884e:	ff                   	(bad)  
 804884f:	ff 02                	incl   (%edx)
 8048851:	00 00                	add    %al,(%eax)
 8048853:	00 00                	add    %al,(%eax)
 8048855:	00 00                	add    %al,(%eax)
 8048857:	00 10                	add    %dl,(%eax)
 8048859:	00 00                	add    %al,(%eax)
 804885b:	00 6c 00 00          	add    %ch,0x0(%eax,%eax,1)
 804885f:	00 c2                	add    %al,%dl
 8048861:	fe                   	(bad)  
 8048862:	ff                   	(bad)  
 8048863:	ff 04 00             	incl   (%eax,%eax,1)
	...

Disassembly of section .ctors:

08049870 <.ctors>:
 8049870:	ff                   	(bad)  
 8049871:	ff                   	(bad)  
 8049872:	ff                   	(bad)  
 8049873:	ff 00                	incl   (%eax)
 8049875:	00 00                	add    %al,(%eax)
	...

Disassembly of section .dtors:

08049878 <.dtors>:
 8049878:	ff                   	(bad)  
 8049879:	ff                   	(bad)  
 804987a:	ff                   	(bad)  
 804987b:	ff 00                	incl   (%eax)
 804987d:	00 00                	add    %al,(%eax)
	...

Disassembly of section .jcr:

08049880 <.jcr>:
 8049880:	00 00                	add    %al,(%eax)
	...

Disassembly of section .dynamic:

08049884 <.dynamic>:
 8049884:	01 00                	add    %eax,(%eax)
 8049886:	00 00                	add    %al,(%eax)
 8049888:	01 00                	add    %eax,(%eax)
 804988a:	00 00                	add    %al,(%eax)
 804988c:	01 00                	add    %eax,(%eax)
 804988e:	00 00                	add    %al,(%eax)
 8049890:	3c 00                	cmp    $0x0,%al
 8049892:	00 00                	add    %al,(%eax)
 8049894:	0c 00                	or     $0x0,%al
 8049896:	00 00                	add    %al,(%eax)
 8049898:	50                   	push   %eax
 8049899:	83 04 08 0d          	addl   $0xd,(%eax,%ecx,1)
 804989d:	00 00                	add    %al,(%eax)
 804989f:	00 5c 87 04          	add    %bl,0x4(%edi,%eax,4)
 80498a3:	08 04 00             	or     %al,(%eax,%eax,1)
 80498a6:	00 00                	add    %al,(%eax)
 80498a8:	68 81 04 08 f5       	push   $0xf5080481
 80498ad:	fe                   	(bad)  
 80498ae:	ff 6f 9c             	ljmp   *-0x64(%edi)
 80498b1:	81 04 08 05 00 00 00 	addl   $0x5,(%eax,%ecx,1)
 80498b8:	3c 82                	cmp    $0x82,%al
 80498ba:	04 08                	add    $0x8,%al
 80498bc:	06                   	push   %es
 80498bd:	00 00                	add    %al,(%eax)
 80498bf:	00 bc 81 04 08 0a 00 	add    %bh,0xa0804(%ecx,%eax,4)
 80498c6:	00 00                	add    %al,(%eax)
 80498c8:	82 00 00             	addb   $0x0,(%eax)
 80498cb:	00 0b                	add    %cl,(%ebx)
 80498cd:	00 00                	add    %al,(%eax)
 80498cf:	00 10                	add    %dl,(%eax)
 80498d1:	00 00                	add    %al,(%eax)
 80498d3:	00 15 00 00 00 00    	add    %dl,0x0
 80498d9:	00 00                	add    %al,(%eax)
 80498db:	00 03                	add    %al,(%ebx)
 80498dd:	00 00                	add    %al,(%eax)
 80498df:	00 60 99             	add    %ah,-0x67(%eax)
 80498e2:	04 08                	add    $0x8,%al
 80498e4:	02 00                	add    (%eax),%al
 80498e6:	00 00                	add    %al,(%eax)
 80498e8:	28 00                	sub    %al,(%eax)
 80498ea:	00 00                	add    %al,(%eax)
 80498ec:	14 00                	adc    $0x0,%al
 80498ee:	00 00                	add    %al,(%eax)
 80498f0:	11 00                	adc    %eax,(%eax)
 80498f2:	00 00                	add    %al,(%eax)
 80498f4:	17                   	pop    %ss
 80498f5:	00 00                	add    %al,(%eax)
 80498f7:	00 28                	add    %ch,(%eax)
 80498f9:	83 04 08 11          	addl   $0x11,(%eax,%ecx,1)
 80498fd:	00 00                	add    %al,(%eax)
 80498ff:	00 20                	add    %ah,(%eax)
 8049901:	83 04 08 12          	addl   $0x12,(%eax,%ecx,1)
 8049905:	00 00                	add    %al,(%eax)
 8049907:	00 08                	add    %cl,(%eax)
 8049909:	00 00                	add    %al,(%eax)
 804990b:	00 13                	add    %dl,(%ebx)
 804990d:	00 00                	add    %al,(%eax)
 804990f:	00 08                	add    %cl,(%eax)
 8049911:	00 00                	add    %al,(%eax)
 8049913:	00 fe                	add    %bh,%dh
 8049915:	ff                   	(bad)  
 8049916:	ff 6f d0             	ljmp   *-0x30(%edi)
 8049919:	82 04 08 ff          	addb   $0xff,(%eax,%ecx,1)
 804991d:	ff                   	(bad)  
 804991e:	ff 6f 02             	ljmp   *0x2(%edi)
 8049921:	00 00                	add    %al,(%eax)
 8049923:	00 f0                	add    %dh,%al
 8049925:	ff                   	(bad)  
 8049926:	ff 6f be             	ljmp   *-0x42(%edi)
 8049929:	82 04 08 00          	addb   $0x0,(%eax,%ecx,1)
	...

Disassembly of section .got:

0804995c <.got>:
 804995c:	00 00                	add    %al,(%eax)
	...

Disassembly of section .got.plt:

08049960 <.got.plt>:
 8049960:	84 98 04 08 00 00    	test   %bl,0x804(%eax)
 8049966:	00 00                	add    %al,(%eax)
 8049968:	00 00                	add    %al,(%eax)
 804996a:	00 00                	add    %al,(%eax)
 804996c:	96                   	xchg   %eax,%esi
 804996d:	83 04 08 a6          	addl   $0xffffffa6,(%eax,%ecx,1)
 8049971:	83 04 08 b6          	addl   $0xffffffb6,(%eax,%ecx,1)
 8049975:	83 04 08 c6          	addl   $0xffffffc6,(%eax,%ecx,1)
 8049979:	83 04 08 d6          	addl   $0xffffffd6,(%eax,%ecx,1)
 804997d:	83                   	.byte 0x83
 804997e:	04 08                	add    $0x8,%al

Disassembly of section .data:

08049980 <.data>:
	...

Disassembly of section .bss:

08049988 <.bss>:
	...

Disassembly of section .comment:

00000000 <.comment>:
   0:	47                   	inc    %edi
   1:	43                   	inc    %ebx
   2:	43                   	inc    %ebx
   3:	3a 20                	cmp    (%eax),%ah
   5:	28 47 4e             	sub    %al,0x4e(%edi)
   8:	55                   	push   %ebp
   9:	29 20                	sub    %esp,(%eax)
   b:	34 2e                	xor    $0x2e,%al
   d:	36 2e 30 20          	ss xor %ah,%cs:(%eax)
  11:	32 30                	xor    (%eax),%dh
  13:	31 31                	xor    %esi,(%ecx)
  15:	30 36                	xor    %dh,(%esi)
  17:	30 33                	xor    %dh,(%ebx)
  19:	20 28                	and    %ch,(%eax)
  1b:	70 72                	jo     8f <random@plt-0x8048301>
  1d:	65 72 65             	gs jb  85 <random@plt-0x804830b>
  20:	6c                   	insb   (%dx),%es:(%edi)
  21:	65 61                	gs popa 
  23:	73 65                	jae    8a <random@plt-0x8048306>
  25:	29 00                	sub    %eax,(%eax)
  27:	47                   	inc    %edi
  28:	43                   	inc    %ebx
  29:	43                   	inc    %ebx
  2a:	3a 20                	cmp    (%eax),%ah
  2c:	28 47 4e             	sub    %al,0x4e(%edi)
  2f:	55                   	push   %ebp
  30:	29 20                	sub    %esp,(%eax)
  32:	34 2e                	xor    $0x2e,%al
  34:	35 2e 32 20 32       	xor    $0x3220322e,%eax
  39:	30 31                	xor    %dh,(%ecx)
  3b:	31 30                	xor    %esi,(%eax)
  3d:	31 32                	xor    %esi,(%edx)
  3f:	37                   	aaa    
  40:	20 28                	and    %ch,(%eax)
  42:	70 72                	jo     b6 <random@plt-0x80482da>
  44:	65 72 65             	gs jb  ac <random@plt-0x80482e4>
  47:	6c                   	insb   (%dx),%es:(%edi)
  48:	65 61                	gs popa 
  4a:	73 65                	jae    b1 <random@plt-0x80482df>
  4c:	29 00                	sub    %eax,(%eax)
