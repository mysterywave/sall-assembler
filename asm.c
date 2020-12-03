#include <stdio.h>
#include <malloc.h>
#include <stdlib.h>
#include <string.h>

//#define DEBUG_PRINTF(fmt, ...) fprintf(stderr, fmt, ##__VA_ARGS__)
#define DEBUG_PRINTF(fmt, ...)

//#define DEBUG_PRINTF2(fmt, ...) fprintf(stderr, fmt, ##__VA_ARGS__)
#define DEBUG_PRINTF2(fmt, ...)

void cause_segfault() {
    int *i = 0;
    *i = 0;
}

// print error message and exit
void fail(char*s) {
    //cause_segfault();
    if(s) {
        exit(fprintf(stderr,"%s\n",s));
    } else {
        exit(fprintf(stderr,"Unknown Error\n"));
    }
}

typedef unsigned char  Opcode;
typedef short          Int;
typedef unsigned short Addr;

// bytecode argument types
enum { REG,     // register
       REGPTR,  // register pointer
       CONPTR,  // constant pointer
       CON,     // constant
       CON_8 }; // 8 bit constant

struct {
    int type;
    Opcode opcode;
    int size;
} mode[] = {
    { REG,    0, 1 },
    { REGPTR, 1, 1 },
    { CONPTR, 2, 2 },
    { CON,    3, 2 },
    { CON_8,  3, 1 },
};

struct opcode_s {
    Opcode opcode;
    char *name;
} opcode[] = {
    { 0x00, "push8" },
    { 0x04, "pop8" },
    { 0x07, "peek8" },
    { 0x08, "push" },
    { 0x0C, "pop" },
    { 0x0F, "peek" },
    { 0x10, "mov8" },
    { 0x20, "mov" },
    { 0x30, "out" },
    { 0x40, "add" },
    { 0x50, "sub" },
    { 0x60, "mul" },
    { 0x70, "div" },
    { 0x80, "mod" },
    { 0x90, "and" },
    { 0xa0, "or" },
    { 0xb0, "xor" },
    { 0xc0, "lsh" },
    { 0xd0, "rsh" },
    { 0xe0, "cmp" },
    { 0xf0, "if" },
    { 0xff, "end" },
    {0,0}
};

struct opcode_s reg_opcode[] = {
    { 0x00, "%ip" },
    { 0x01, "%sp" },
    { 0x02, "%oo" },
    { 0x03, "%r1" },
    { 0x04, "%r2" },
    { 0x05, "%r3" },
    { 0x06, "%r4" },
    {0,0}
};

enum { TEXT,DATA,DATA8,STRING,EMPTY,REGISTER };
char *types[] = { "TEXT","DATA","BYTE","STRN","EMTY","REG." };
typedef struct mem {
    Addr addr;          // address of this opcode or data element
    int type;           // type: TEXT, DATA, etc
    char *lab;          // optional label
    char *s;            // text of opcode
    int size;           // size of element in bytes
    Opcode opcode;      // opcode value
    Int val;            // data value, also register number
    int indirect;       // 1 if indirect, otherwise 0
    struct mem *arg1;   // instruction argument 1
    struct mem *arg2;   // instruction argument 2
    struct mem *next;   // link
} mem;

mem *root = 0; // root of linked list

// locate last element of of linked list
mem *end() {
    mem *m = root;
    while (m->next) m=m->next;
    return m;
}

int ishexdigit(char c) {
    return ((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F'));
}
int hexdigit(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    fprintf(stderr, "I don't know where but there is an invalid hex digit: '%c'\n", c);
    exit(1);
}

// parse C style string/char escape sequences
int cesc(char *p, Int *val) {
    if (*p =='\\') {
        switch (p[1]) {
            case '0': *val = '\0'; return 2;
            case 'a': *val = '\a'; return 2;
            case 'b': *val = '\b'; return 2;
            case 'e': *val = 27; return 2;
            case 'f': *val = '\f'; return 2;
            case 'n': *val = '\n'; return 2;
            case 'r': *val = '\r'; return 2;
            case 't': *val = '\t'; return 2;
            case 'v': *val = '\v'; return 2;
            case '\\': *val = '\\'; return 2;
            case '\'': *val = '\''; return 2;
            case '\"': *val = '\"'; return 2;
            case '\?': *val = '\?'; return 2;
        }
        if (p[1] == 'x') {
            int x = hexdigit(p[2]) << 4 | hexdigit(p[3]);
            *val = x;
            return 4;
        } else if (p[1] >= '0' && p[1] <= '9') {
            int x = strtol(p,0,0);
            *val = x;
            return 5;
        }
    }
    *val = *p;
    return 1;
}

void sesc(char *s) {
    char *p = s;
    char *q = s;
    Int i;
    while(*p) {
        p += cesc(p, &i);
        *q = i;
        q++;
    }
    *q = '\0';
}


// convert a token to an integer value
// return 0 if cannot be converted
int val(char*tok,Int*v,int*w) {
    int x;

    if (!strncasecmp(tok,"0x",2)) {
        // hexadecimal
        x=strtol(tok+2,0,16);
        *v=x;
        *w=strlen(tok)/2-1;
    } else if (!strncasecmp(tok,"0b",2)) {
        // binary
        x=strtol(tok+2,0,2);
        *v=x;
        *w=1+(strlen(tok)-3)/8;
    } else if (*tok=='\'') {
        // single character
        cesc(tok+1,v);
        *w=1;
    } else if ((*tok=='-'||*tok=='+') || (*tok>='0'&&*tok<='9')) {
        // decimal
        x = strtol(tok,0,10);
        //printf("  strtol(%s)=%d\n",tok,x);
        if (x < 0)
            *w=2;
        else if (((x) & ~0xFF)==0)
            *w=1;
        else if (((x) & ~0xFFFF)==0)
            *w=2;
        else fail(0);
        *v = x;
    }
    else return 0;

    if (*w>2)
        fail("constant will not fit in 16 bits");
    return 1;
}

Opcode addressing_opcode(int addrmode) {
    int i;
    for (i=0; i<5; i++) {
        if (addrmode == mode[i].type)
            return mode[i].opcode;
    }
    fail(0);
}

Opcode addressing_mode(char *instruction_name, mem *m) {
    if(strcasecmp(instruction_name,"pop") == 0 && m->type == DATA && !m->indirect) {
        fail("pop doesn't take a constant");
    }
    if(strcasecmp(instruction_name,"pop8") == 0 && m->type == DATA && !m->indirect) {
        fail("pop8 doesn't take a constant");
    }
    if(strcasecmp(instruction_name,"peek") == 0 && !(m->type == DATA && !m->indirect)) {
        fail("peek only takes a constant");
    }
    if(strcasecmp(instruction_name,"peek8") == 0 && !(m->type == DATA && !m->indirect)) {
        fail("peek8 only takes a constant");
    }
    int addrmode = 0;
    if (m->type == REGISTER) {
        if (m->indirect) {
            m->size = 1;
            addrmode = REGPTR;
        } else {
            m->size = 1;
            addrmode = REG;
        }
    } else if (m->type == TEXT) {
        m->size = 2;
        addrmode = CON; // label
    } else if (m->type == DATA) {
        if (m->indirect) {
            m->size = 2;
            addrmode = CONPTR;
        } else {
            if(strcasecmp(instruction_name,"push8") == 0 || strcasecmp(instruction_name,"mov8") == 0 || strcasecmp(instruction_name,"out") == 0) {
                m->size = 1;
                addrmode = CON_8;
            } else {
                m->size = 2;
                addrmode = CON;
            }
        }
    } else {
        printf("unknown type: %d\n", m->type);
        fail(0);
    }
    m->opcode = addressing_opcode(addrmode);
    return addrmode;
}

// insert an element into our 'mem' database
mem *ins(int type, char*tok, char**ll){
    mem *m = malloc(sizeof *m);
    bzero(m, sizeof(*m));

    if (ll) {
        m->lab=*ll; // attach label to asm element
        *ll=0; // set label to null, don't reuse
    }

    // linked list stuff
    if (!root)
        root=m;
    else
        end()->next=m;

    // is this NOT an integer constant?
    if (!val(tok,&m->val,&m->size)) {
        m->s=strdup(tok); // nope it is an opcode or string or something
        if (type==STRING) {
            sesc(m->s);
            m->size=strlen(m->s); // if string set length
        }
    }

    m->type=type;

    if (m->type==DATA) {
        DEBUG_PRINTF("ins: {%s},\033[36m%s\033[0m,\033[33m%s\033[0m,%d,\033[31;1m0x%hx(%hd)\033[0m\n",
            types[m->type],
            m->lab?m->lab:"",
            m->s?m->s:"",
            m->size,m->val,m->val);
    } else if (m->type==STRING) {
        DEBUG_PRINTF("ins: <%s>,\033[36m%s\033[0m,\033[32;1m%s\033[0m,%d,\033[31;1m0x%hx(%hd)\033[0m\n",
            types[m->type],
            m->lab?m->lab:"",
            m->s?m->s:"",
            m->size,m->val,m->val);
    } else if (m->type==REGISTER) {
        DEBUG_PRINTF("ins: [%s],\033[36m%s\033[0m,\033[33m%s\033[0m\n",
            types[m->type],
            m->lab?m->lab:"",
            m->s?m->s:"");
    } else if (m->type==EMPTY) {
        DEBUG_PRINTF("ins: [%s],\033[36m%s\033[0m:\n",
            types[m->type], m->lab?m->lab:"");
    } else {
        DEBUG_PRINTF("ins: [%s],\033[36m%s\033[0m,\033[33m%s\033[0m,%d\n",
            types[m->type],
            m->lab?m->lab:"",
            m->s?m->s:"",
            m->size);
    }
    return m;
}

 // read a file into a character buffer
char* slurp(FILE *fp) {
    long size = 1024;
    char *buffer = malloc(size);
    int i = 0;
    int c;

    while ((c = getc(fp)) != EOF) {
        if (i == size-1) {
            char *new = realloc(buffer, size *= 2);
            if (new) buffer = new;
            else {
                free(buffer);
                fail(0);
            }
        }
        buffer[i++] = c;
    }
    return buffer;
}

// parse a character buffer
char* parse(char *b) {
    char *lastlab=0; // the last label we saw in the source file; attach to next asm element
    char *p; // current pos in string -- the starting point for our current token
    char *q; // the end of our current token or element
    int state=0; // flag to keep track of if we have seen a 'store' tag
    int w; // width of data in bytes, always 1 or 2
    Int v; // value of data

    // parse file, one byte at a time
    for(p=b; *p; p++) {
        // skip over whitespace
        if(*p==' ' || *p=='\t' || *p=='\n' || *p==',') continue;

        // skip over comments
        if(*p == '#') {
            for(++p; *p && *p != '\n' ; p++);
            continue;
        }

        //printf("%c\n", *p);
        // is this a quoted string? or character constant?
        if(*p=='"' || *p=='\'') {
            // find end quote
            for(q = p+1; *q && *q != *p; q++)
                ;

            // replace end quote with '\0' so we can copy it
            int r = *q;
            *q = 0;

            if (*p=='"')
                ins(STRING,p+1,&lastlab);
            else if (*p=='\'')
                ins(DATA,p,&lastlab);

            // restore the end quote
            *q=r;
            p=q+1; // skip current pos past endquote
            continue; // staaahp!!
        }

        // p is start of token, find end of token ("q")
        for (q=p; *q && !strchr("\n \t,",*q); q++);

        // stick a '\0' in so we can copy
        int r=*q; *q=0;

        int n=strlen(p);
        if (p[n-1]==':') {
            // oh key, a label. save a copy
            if (lastlab) {
                ins(EMPTY,"",&lastlab);
                free(lastlab);
            }
            lastlab=strndup(p,n-1);
        } else if (val(p,&v,&w)) {
            // a data constant
            mem *m = ins(DATA,p,&lastlab);
            if (state==1) {
                m->size = m->val;
                m->val = 0;
                state = 0;
            }
        } else if (!strcasecmp(p,"store")) {
            state=1;
        } else if (*p == '[') {
            if(*(q - 1) != ']') {
                fail("close your square brackets");
            }
            *(q - 1) = '\0';
            // an indirect pointer argument, figure out whether a register or a constant
            mem *m;
            ++p; // slip the [
            while (*p && (*p==' ' || *p=='\t')) ++p; // skep any whitespaaace that follows it

            if (*p == '%') {
                m = ins(REGISTER,p,&lastlab);
            } else if (val(p,&v,&w)) {
                m = ins(DATA,p,&lastlab);
            } else fail(0);

            *(q - 1) = ']';
            m->indirect = 1; // oh yeah its a pointer
        } else if (*p == '%') {
            ins(REGISTER,p,&lastlab); // jes a plain ole reguster
        } else {
            mem *m;
            if (*p == '%') {
                m = ins(REGISTER,p,&lastlab); // wuts with all the registers
            } else if (val(p,&v,&w)) {
                m = ins(DATA,p,&lastlab); // why we do this again?
            } else {
                //printf("opcode:\"%s\"\n", p);
                mem*m=ins(TEXT,p,&lastlab); // aaaah an opcode. or something
                int i;
                for (i=0; opcode[i].name; i++) {
                    if (!strcasecmp(opcode[i].name, p))
                        m->opcode = opcode[i].opcode;
                }
            }
        }

        // get rid of the '\0' and restore wahteer was there before
        *q=r;
        p=q; // finished, skip past end of token
    }

    if (lastlab) {
        // if we found a label but are at end of code, add an "empty" label place-marker to makr the address
        ins(EMPTY,"",&lastlab);
    }
    return b;
}

void setReg(mem *m) {
    int r;
    for (r=0; reg_opcode[r].name; r++) {
        if (!strcasecmp(reg_opcode[r].name, m->s)) {
            m->val = reg_opcode[r].opcode;
            return;
        }
    }
    fail("weird register");
}

// add addresses and addressing modes
char* fixup(char*ptu) {
    mem*m;
    Addr addr = 0; // current address

    for(m=root;m;m=m->next) {
        m->addr = addr;
        
        /*printf("fixing up %d\n", m->type);
        if(m->type == 0) {
            printf("  \"%s\"\n", m->s);
        }
        if(m->arg1) {
            printf("arg1: %d\n", m->arg1->type);
        }
        if(m->arg2) {
            printf("arg2: %d\n", m->arg2->type);
        }*/

        if (m->type==TEXT) { // aka CODE
            int i;
            for (i=0; opcode[i].name; i++) {
                if (!strcasecmp(opcode[i].name, m->s)) {
                    m->opcode = opcode[i].opcode;
                    break;
                }
            }

            // do we have arguments
            if ((strcasecmp(m->s,"end") == 0)) {
                // no
                addr += 1; // one byte
            } else if ((strcasecmp(m->s,"push8") == 0) || (strcasecmp(m->s,"pop8") == 0) || (strcasecmp(m->s,"peek8") == 0) || (strcasecmp(m->s,"push") == 0) || (strcasecmp(m->s,"pop") == 0) || (strcasecmp(m->s,"peek") == 0)) {
                // yes, 2 arguments
                if (!m->next)
                    fail("expected an arg");
                // remove from linked list and attach to node
                m->arg1=m->next;
                m->next=m->next->next;

                // what are the addressing modes?
                int mode1 = addressing_mode(m->s, m->arg1);
                // what is the total size of this instruction + args?
                addr += 1 + m->arg1->size;
                // put together de opcode for this instruction
                m->opcode = m->opcode | m->arg1->opcode;

                // figure out register number
                if (m->arg1->type == REGISTER) {
                    setReg(m->arg1);
                }
            } else {
                // yes, 2 arguments
                if (!m->next || !m->next->next)
                    fail("expected two args");
                // remove from linked list and attach to node
                m->arg1=m->next;
                m->arg2=m->next->next;
                m->next=m->next->next->next;

                // what are the addressing modes?
                int mode1 = addressing_mode(m->s, m->arg1);
                int mode2 = addressing_mode(m->s, m->arg2);
                // what is the total size of this instruction + args?
                addr += 1 + m->arg1->size + m->arg2->size;
                // put together de opcode for this instruction
                m->opcode = m->opcode | m->arg1->opcode | (m->arg2->opcode << 2);

                // figure out register number
                if (m->arg1->type == REGISTER) {
                    setReg(m->arg1);
                }
                // mebbe do it again
                if (m->arg2->type == REGISTER) {
                    setReg(m->arg2);
                }
            }
        } else {
            addr += m->size; // data elements know their own size
        }
    }
    return ptu;
}

Addr label_addr(char *lab) {
    mem*m;
    for(m=root; m; m=m->next) {
        if (m->lab && !strcmp(m->lab, lab))
            return m->addr;
    }
    return 0xDEAD;
}

// make a pretty print of reconstructed source code
char *pretty_print(char*tru) {
    mem *m;
    DEBUG_PRINTF2("SOURCE LISTING:\n");
    for(m=root;m;m=m->next) {
        if (m->type==TEXT) {
            if (m->arg1 && m->arg2) {
                DEBUG_PRINTF2("%04hx %s%c%*s %s ", m->addr,m->lab?m->lab:"", m->lab?':':' ', (int)(m->lab?15-strlen(m->lab):15),"",m->s);
                if (m->arg1->type == DATA) {
                    if (m->arg1->indirect) {
                        DEBUG_PRINTF2("[%hd] ", m->arg1->val);
                    } else {
                        DEBUG_PRINTF2("%hd ", m->arg1->val);
                    }
                } else {
                    if (m->arg1->indirect) {
                        DEBUG_PRINTF2("[%s] ", m->arg1->s);
                    } else {
                        DEBUG_PRINTF2("%s ", m->arg1->s);
                    }
                }
                if (m->arg2->type == DATA) {
                    if (m->arg2->indirect) {
                        DEBUG_PRINTF2("[%hd]\n", m->arg2->val);
                    } else {
                        DEBUG_PRINTF2("%hd\n", m->arg2->val);
                    }
                } else {
                    if (m->arg2->indirect) {
                        DEBUG_PRINTF2("[%s]\n", m->arg2->s);
                    } else {
                        DEBUG_PRINTF2("%s\n", m->arg2->s);
                    }
                }
            } else if (m->arg1) {
                DEBUG_PRINTF2("%04hx %s%c%*s %s ", m->addr,m->lab?m->lab:"", m->lab?':':' ', (int)(m->lab?15-strlen(m->lab):15),"",m->s);
                if (m->arg1->type == DATA) {
                    if (m->arg1->indirect) {
                        DEBUG_PRINTF2("[%hd]\n", m->arg1->val);
                    } else {
                        DEBUG_PRINTF2("%hd\n", m->arg1->val);
                    }
                } else {
                    if (m->arg1->indirect) {
                        DEBUG_PRINTF2("[%s]\n", m->arg1->s);
                    } else {
                        DEBUG_PRINTF2("%s\n", m->arg1->s);
                    }
                }
            } else {
                DEBUG_PRINTF2("%04hx %s%c%*s %s\n", m->addr,
                    m->lab?m->lab:"", m->lab?':':' ', (int)(m->lab?15-strlen(m->lab):15),"",
                    m->s?m->s:"");
            }
        } else if (m->type==STRING) {
            DEBUG_PRINTF2("%04hx %s%c%*s \"%s\"\n", m->addr,
                m->lab?m->lab:"", m->lab?':':' ', (int)(m->lab?15-strlen(m->lab):15),"",
                m->s);
        } else if(m->size==1) {
            DEBUG_PRINTF2("%04hx %s%c%*s 0x%02hhx\n", m->addr,
                m->lab?m->lab:"", m->lab?':':' ', (int)(m->lab?15-strlen(m->lab):15),"",
                m->val);
        } else if(m->size==2) {
            DEBUG_PRINTF2("%04hx %s%c%*s 0x%04hx\n", m->addr,
                m->lab?m->lab:"", m->lab?':':' ', (int)(m->lab?15-strlen(m->lab):15),"",
                m->val);
        } else if(m->type==DATA) {
            DEBUG_PRINTF2("%04hx %s%c%*s store[%d]\n", m->addr,
                m->lab?m->lab:"", m->lab?':':' ', (int)(m->lab?15-strlen(m->lab):15),"",
                m->size);
        } else {
            DEBUG_PRINTF2("%04hx %s%c%*s %s\n", m->addr,
                m->lab?m->lab:"", m->lab?':':' ', (int)(m->lab?15-strlen(m->lab):15),"",
                m->s);
        }
    }
    return tru;
}

// make a pretty print of binary bytecodes
char *gen_pretty_print(char*tru) {
    mem *m;

    pretty_print(0);

    DEBUG_PRINTF2("BINARY OUTPUT:\n");
    for(m=root; m; m=m->next) {
        if (m->type == TEXT) {
            DEBUG_PRINTF2("%04hx | %02hhx", m->addr, m->opcode);
            if (m->arg1) {
                if (m->arg1->type == TEXT)
                    //printf(" %s", m->arg1->s);
                    DEBUG_PRINTF2(" %04x", label_addr(m->arg1->s));
                else if (m->arg1->type == REGISTER)
                    DEBUG_PRINTF2(" %02x", m->arg1->val);
                else if (m->arg1->type == DATA)
                    if(m->arg1->size == 2) {
                        DEBUG_PRINTF2(" %04x", m->arg1->val);
                    } else {
                        DEBUG_PRINTF2(" %02x", m->arg1->val);
                    }
                else
                    DEBUG_PRINTF2(" %04x", 0);
            }
            if (m->arg2) {
                if (m->arg2->type == TEXT)
                    //printf(" %s", m->arg2->s);
                    DEBUG_PRINTF2(" %04x", label_addr(m->arg2->s));
                else if (m->arg2->type == REGISTER)
                    DEBUG_PRINTF2(" %02x", m->arg2->val);
                else if (m->arg2->type == DATA)
                    if(m->arg2->size == 2) {
                        DEBUG_PRINTF2(" %04x", m->arg2->val);
                    } else {
                        DEBUG_PRINTF2(" %02x", m->arg2->val);
                    }
                else
                    DEBUG_PRINTF2(" %04x", 0);
            }
        } else if (m->type == DATA) {
            if (m->size == 1)
                DEBUG_PRINTF2("%04hx | %02hhx", m->addr, m->val);
            else if (m->size == 2)
                DEBUG_PRINTF2("%04hx | %04hx", m->addr, m->val);
            else if (m->size > 2) {
                DEBUG_PRINTF2("%04hx |", m->addr);
                int bytes = 0;
                do {
                    int num = bytes + 24;
                    if (num > m->size) num = m->size;
                    while (bytes < num) {
                        DEBUG_PRINTF2(" %02x", 0x00);
                        bytes++;
                    }
                    if (bytes < m->size)
                        DEBUG_PRINTF2("\n     |");
                } while (bytes < m->size);
            }
        } else if (m->type == STRING) {
            DEBUG_PRINTF2("%04hx | ", m->addr);
            char *p = m->s;
            for ( ; *p; p++)
                DEBUG_PRINTF2("%02hhx ", *p);
            DEBUG_PRINTF2("%02x", 0);
        } else if (m->type == EMPTY) {
            continue;
        }
        DEBUG_PRINTF2("\n");
    }
    return tru;
}

void fputw(unsigned short word, FILE *fp)
{
    fputc((word >> 8) & 0xFF, fp);
    fputc(word & 0xFF, fp);
}

// write binary bytecode to a file
// same as pretty print, except binary
char *gen_binary(FILE *fpout) {
    mem *m;

    for(m=root; m; m=m->next) {
        if (m->type == TEXT) {
            fputc(m->opcode, fpout);
            if (m->arg1) {
                if (m->arg1->type == TEXT)
                    fputw(label_addr(m->arg1->s), fpout);
                else if (m->arg1->type == REGISTER)
                    fputc(m->arg1->val, fpout);
                else if (m->arg1->type == DATA)
                    if(m->arg1->size == 2) {
                        fputw(m->arg1->val, fpout);
                    } else {
                        fputc(m->arg1->val, fpout);
                    }
                else
                    fputw(0, fpout);
            }
            if (m->arg2) {
                if (m->arg2->type == TEXT)
                    fputw(label_addr(m->arg2->s), fpout);
                else if (m->arg2->type == REGISTER)
                    fputc(m->arg2->val, fpout);
                else if (m->arg2->type == DATA)
                    if(m->arg2->size == 2) {
                        fputw(m->arg2->val, fpout);
                    } else {
                        fputc(m->arg2->val, fpout);
                    }
                else
                    fputw(0, fpout);
            }
        } else if (m->type == DATA) {
            if (m->size == 1)
                fputc(m->val, fpout);
            else if (m->size == 2)
                fputw(m->val, fpout);
            else if (m->size > 2) {
                int bytes = 0;
                do {
                    int num = bytes + 24;
                    if (num > m->size) num = m->size;
                    while (bytes < num) {
                        fputc(0x00, fpout);
                        bytes++;
                    }
                } while (bytes < m->size);
            }
        } else if (m->type == STRING) {
            char *p;
            for (p = m->s; *p; p++) fputc(*p, fpout);
            /*fputw(m->addr, fpout);
            char *p = m->s;
            for ( ; *p; p++)
                fputc(*p, fpout);
            fputc(0, fpout);*/
        } else if (m->type == EMPTY) {
            continue;
        }
    }
}

// code generator
void *gen(void *ptr) {
    gen_pretty_print(ptr);
    FILE *fpout = fopen("asm.bin", "wb");
    if (fpout) {
        gen_binary(fpout);
        fclose(fpout);
    }
    return ptr;
}

int main(int argc, char **argv) {
    if (argc == 2) {
        FILE *fp = fopen(argv[1],"r");
        if (fp) {
            DEBUG_PRINTF2("Reading file...\n");
            char *file = slurp(fp);
            DEBUG_PRINTF2("Parsing...\n");
            char *parsed = parse(file);
            DEBUG_PRINTF2("Fixing up...\n");
            char *fixed = fixup(parsed);
            DEBUG_PRINTF2("Writing output...\n");
            void *out = gen(fixed);
            free(out);
            fclose(fp);
        }
    } else {
        DEBUG_PRINTF2("Reading from stdin...\n");
        char *file = slurp(stdin);
        DEBUG_PRINTF2("Parsing...\n");
        char *parsed = parse(file);
        DEBUG_PRINTF2("Fixing up...\n");
        char *fixed = fixup(parsed);
        DEBUG_PRINTF2("Writing output...\n");
        void *out = gen(fixed);
        free(out);
    }
    return 0;
}

