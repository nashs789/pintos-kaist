#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/synch.h"
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
bool remove (const char *file);
int write(int fd, const void *buffer, unsigned size);
int open(const char *file);
struct file *add_file_to_fd_table(struct file *file);
struct file *fd_to_struct_filep(int fd);
int filesize(int fd);
int read(int fd, void *buffer, unsigned size);
void seek (int fd, unsigned position);
void tell(int fd);

struct lock filesys_lock;

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

	lock_init(&filesys_lock);
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
	case SYS_REMOVE:
		remove(f->R.rdi);
		break;
	case SYS_OPEN:
		open(f->R.rdi);
		break;
	case SYS_FILESIZE:
		filesize(f->R.rdi);
		break;
	case SYS_READ:
		read(f->R.rdi, f->R.rsi, f->R.rdx);
		break;
	case SYS_WRITE:
		f->R.rax = write(f->R.rdi, f->R.rsi, f->R.rdx);
		break;
	case SYS_SEEK:
		seek(f->R.rdi, f->R.rsi);	
		break;
	case SYS_TELL:
		tell(f->R.rdi);		
		break;
	case SYS_CLOSE:
		close(f->R.rdi);
		break;
	default:
		thread_exit ();
		break;
	}

	// printf("system call!\n");

	// thread_exit ();

		// switch(sys_number) {
		// case SYS_HALT:
		// 	halt();
		// case SYS_EXIT:
		// 	exit(f->R.rdi);
		// case SYS_FORK:
		// 	fork(f->R.rdi);		
		// case SYS_EXEC:
		// 	exec(f->R.rdi);
		// case SYS_WAIT:
		// 	wait(f->R.rdi);
		// case SYS_CREATE:
		// 	create(f->R.rdi, f->R.rsi);		
		// case SYS_REMOVE:
		// 	remove(f->R.rdi);		
		// case SYS_OPEN:
		// 	open(f->R.rdi);		
		// case SYS_FILESIZE:
		// 	filesize(f->R.rdi);
		// case SYS_READ:
		// 	read(f->R.rdi, f->R.rsi, f->R.rdx);
		// case SYS_WRITE:
		// 	write(f->R.rdi, f->R.rsi, f->R.rdx);		
		// case SYS_SEEK:
		// 	seek(f->R.rdi, f->R.rsi);		
		// case SYS_TELL:
		// 	tell(f->R.rdi);		
		// case SYS_CLOSE:
		// 	close(f->R.rdi);
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
	cur->exit_status = status;
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

bool remove (const char *file) {
	check_address(file);
	if (filesys_remove(file)) {
		return true;
	} else {
		return false;
	}
}

int write(int fd, const void *buffer, unsigned size){
	check_address(buffer);
	struct file *fileobj = fd_to_struct_filep(fd);
	int read_count;
	if(fd == STDOUT_FILENO){
		putbuf(buffer, size);
		read_count = size;
	}
	else if(fd == STDIN_FILENO)
		return -1;
	else{
		lock_acquire(&filesys_lock);
		read_count = file_write(fileobj, buffer, size);
		lock_release(&filesys_lock);
	}
}

int open(const char *file){
	check_address(file);
	struct file *file_obj = filesys_open(file);

	if(file_obj == NULL)
		return -1;
	int fd = add_file_to_fd_table(file_obj);

	if(fd == -1)
		file_close(file_obj);
}

struct file *add_file_to_fd_table(struct file *file){
	struct thread *t = thread_current();
	struct file **fdt = t->file_descriptor_table;
	int fd = t->fdidx; // fd값은 2부터 출발

	while(t->file_descriptor_table[fd] != NULL && fd < FDCOUNT_LIMIT){
		fd++;
	}

	if(fd >= FDCOUNT_LIMIT)
		return -1;

	t->fdidx = fd;
	fdt[fd] = file;
	return fd;
}

int filesize(int fd){
	struct file *fileobj = fd_to_struct_filep(fd);
	if(fileobj == NULL)
		return -1;
	file_length(fileobj);
}

/*  fd 값을 넣으면 해당 file을 반환하는 함수 */
struct file *fd_to_struct_filep(int fd){
	if(fd < 0 || fd >= FDCOUNT_LIMIT)
		return NULL;
	
	struct thread *t = thread_current();
	struct file **fdt = t->file_descriptor_table;

	struct file *file = fdt[fd]; //
	return file;
}

int read(int fd, void *buffer, unsigned size){
	// 유효한 주소인지부터 체크
	check_address(buffer); //버퍼 시작 주소 체크
	check_address(buffer + size - 1); //버퍼 끝 주소도 유저 영역 내에 있는지 체크
	unsigned char *buf = buffer;
	int read_count;

	struct file *fileobj = fd_to_struct_filep(fd);

	if(fileobj == NULL)
		return -1;

	//STDIN 일 때 : keyboard로 입력 받음
	if(fd == STDIN_FILENO){
		char key;
		for(int read_count = 0; read_count < size; read_count++){
			key = input_getc();
			*buf++ = key;
			if (key == '\0') // 엔터값
				break;
		}
	}
	//STDOUT일 때: -1 반환 
	else if (fd == STDOUT_FILENO)
		return -1;
	else{
		lock_acquire(&filesys_lock);
		read_count = file_read(fileobj, buffer, size);// 파일 읽어들일 동안만 lock 걸어준다.
		lock_release(&filesys_lock);
	}
	return read_count;
}

void seek(int fd, unsigned position){
	if(fd < 2) //1 , 2 는 stdin, stdio 기 때문에.
		return;
	struct file *file = fd_to_struct_filep(fd);
	check_address(file);
	if(file == NULL)
		return;
	file_seek(file, position); //file의 pos 는 position 이 된다.
}

void tell(int fd){
	if(fd < 2) //1 , 2 는 stdin, stdio 기 때문에.
		return;
	struct file *file = fd_to_struct_filep(fd);
	check_address(file);
	if(file == NULL)
		return;
	file_tell(fd); //file의 현재 pos
}

void close(int fd){
	struct file *file = fd_to_struct_filep(fd);
	if(file == NULL)
		return;
	file_close(file);
}