#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/loader.h"
#include "userprog/gdt.h"
#include "threads/flags.h"
#include "intrinsic.h"


void syscall_entry (void);
void syscall_handler (struct intr_frame *);

void halt(void);
void exit(int status);
void check_address(void *addr);
bool create (const char *file, unsigned initial_size) ;

/* System call.
 *
 * Previously system call services was handled by the interrupt handler
 * (e.g. int 0x80 in linux). However, in x86-64, the manufacturer supplies
 * efficient path for requesting the system call, the `syscall` instruction.
 *
 * The syscall instruction works by reading the values from the the Model
 * Specific Register (MSR). For the details, see the manual. */

#define MSR_STAR 0xc0000081         /* Segment selector msr */
#define MSR_LSTAR 0xc0000082        /* Long mode SYSCALL target */
#define MSR_SYSCALL_MASK 0xc0000084 /* Mask for the eflags */

void
syscall_init (void) {
	write_msr(MSR_STAR, ((uint64_t)SEL_UCSEG - 0x10) << 48  |
			((uint64_t)SEL_KCSEG) << 32);
	write_msr(MSR_LSTAR, (uint64_t) syscall_entry);

	/* The interrupt service rountine should not serve any interrupts
	 * until the syscall_entry swaps the userland stack to the kernel
	 * mode stack. Therefore, we masked the FLAG_FL. */
	write_msr(MSR_SYSCALL_MASK,
			FLAG_IF | FLAG_TF | FLAG_DF | FLAG_IOPL | FLAG_AC | FLAG_NT);
}

/* The main system call interface */
void
syscall_handler (struct intr_frame *f UNUSED) {
	// TODO: Your implementation goes here.
	
	switch (f->R.rax)
	{
	case SYS_HALT:
		halt();
		break;
	case SYS_EXIT:
		exit(f->R.rdi);
		break;
	case SYS_CREATE:
		create(f->R.rdi, f->R.rsi);
		break;
	case SYS_WRITE:
		putbuf(f->R.rsi,f->R.rdx);
		break;
	default:
		break;
	}

	// printf("system call!\n");

	// thread_exit ();
}

void check_address(void *addr) {
	struct thread *t = thread_current();
	/* --- Project 2: User memory access --- */
	// if (!is_user_vaddr(addr)||addr == NULL) 
	//-> 이 경우는 유저 주소 영역 내에서도 할당되지 않는 공간 가리키는 것을 체크하지 않음. 그래서 
	// pml4_get_page를 추가해줘야!
	if (!is_user_vaddr(addr) || addr == NULL){
		exit(-1);
	}
}

void halt(){
	power_off();
}

void exit(int status) { 
	struct thread *cur = thread_current();
	// cur->exit_status = status;
	printf("%s: exit(%d)\n", cur->name, status);
	thread_exit(); /* Thread를 종료시키는 함수 */
}

/* 파일 생성하는 시스템 콜 */
bool create (const char *file, unsigned initial_size) {
	/* 성공이면 true, 실패면 false */
	check_address(file);
	if (filesys_create(file, initial_size)) {
		return true;
	}
	else {
		return false;
	}
}