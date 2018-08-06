;
; Bareflank Extended APIs
;
; Copyright (C) 2015 Assured Information Security, Inc.
; Author: Rian Quinn        <quinnr@ainfosec.com>
; Author: Brendan Kerrigan  <kerriganb@ainfosec.com>
;
; This library is free software; you can redistribute it and/or
; modify it under the terms of the GNU Lesser General Public
; License as published by the Free Software Foundation; either
; version 2.1 of the License, or (at your option) any later version.
;
; This library is distributed in the hope that it will be useful,
; but WITHOUT ANY WARRANTY; without even the implied warranty of
; MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
; Lesser General Public License for more details.
;
; You should have received a copy of the GNU Lesser General Public
; License along with this library; if not, write to the Free Software
; Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA

bits 64
default rel

extern default_isr

section .text

%macro PUSHALL 0
    sub rsp, 16
    movups [rsp], xmm0
    sub rsp, 16
    movups [rsp], xmm1
    sub rsp, 16
    movups [rsp], xmm2
    sub rsp, 16
    movups [rsp], xmm3
    sub rsp, 16
    movups [rsp], xmm4
    sub rsp, 16
    movups [rsp], xmm5
    sub rsp, 16
    movups [rsp], xmm6
    sub rsp, 16
    movups [rsp], xmm7

    push rax
    push rbx
    push rcx
    push rdx
    push rbp
    push rsi
    push rdi
    push r8
    push r9
    push r10
    push r11
    push r12
    push r13
    push r14
    push r15

    ;
    ; make the vic available from the IDT
    ;
    mov r15, [gs:0x0088]
    push r15

%endmacro

%macro POPALL 0
    pop r15
    mov [gs:0x0088], r15
    pop r15
    pop r14
    pop r13
    pop r12
    pop r11
    pop r10
    pop r9
    pop r8
    pop rdi
    pop rsi
    pop rbp
    pop rdx
    pop rcx
    pop rbx
    pop rax

    movups xmm7, [rsp]
    add rsp, 16
    movups xmm6, [rsp]
    add rsp, 16
    movups xmm5, [rsp]
    add rsp, 16
    movups xmm4, [rsp]
    add rsp, 16
    movups xmm3, [rsp]
    add rsp, 16
    movups xmm2, [rsp]
    add rsp, 16
    movups xmm1, [rsp]
    add rsp, 16
    movups xmm0, [rsp]
    add rsp, 16
%endmacro

%macro ISR 1
    global _isr%1
    _isr%1:
        PUSHALL
        mov rdi, %1
        mov rsi, rsp
        call default_isr wrt ..plt
        POPALL
        iretq
%endmacro

ISR 32
ISR 33
ISR 34
ISR 35
ISR 36
ISR 37
ISR 38
ISR 39
ISR 40
ISR 41
ISR 42
ISR 43
ISR 44
ISR 45
ISR 46
ISR 47
ISR 48
ISR 49
ISR 50
ISR 51
ISR 52
ISR 53
ISR 54
ISR 55
ISR 56
ISR 57
ISR 58
ISR 59
ISR 60
ISR 61
ISR 62
ISR 63
ISR 64
ISR 65
ISR 66
ISR 67
ISR 68
ISR 69
ISR 70
ISR 71
ISR 72
ISR 73
ISR 74
ISR 75
ISR 76
ISR 77
ISR 78
ISR 79
ISR 80
ISR 81
ISR 82
ISR 83
ISR 84
ISR 85
ISR 86
ISR 87
ISR 88
ISR 89
ISR 90
ISR 91
ISR 92
ISR 93
ISR 94
ISR 95
ISR 96
ISR 97
ISR 98
ISR 99
ISR 100
ISR 101
ISR 102
ISR 103
ISR 104
ISR 105
ISR 106
ISR 107
ISR 108
ISR 109
ISR 110
ISR 111
ISR 112
ISR 113
ISR 114
ISR 115
ISR 116
ISR 117
ISR 118
ISR 119
ISR 120
ISR 121
ISR 122
ISR 123
ISR 124
ISR 125
ISR 126
ISR 127
ISR 128
ISR 129
ISR 130
ISR 131
ISR 132
ISR 133
ISR 134
ISR 135
ISR 136
ISR 137
ISR 138
ISR 139
ISR 140
ISR 141
ISR 142
ISR 143
ISR 144
ISR 145
ISR 146
ISR 147
ISR 148
ISR 149
ISR 150
ISR 151
ISR 152
ISR 153
ISR 154
ISR 155
ISR 156
ISR 157
ISR 158
ISR 159
ISR 160
ISR 161
ISR 162
ISR 163
ISR 164
ISR 165
ISR 166
ISR 167
ISR 168
ISR 169
ISR 170
ISR 171
ISR 172
ISR 173
ISR 174
ISR 175
ISR 176
ISR 177
ISR 178
ISR 179
ISR 180
ISR 181
ISR 182
ISR 183
ISR 184
ISR 185
ISR 186
ISR 187
ISR 188
ISR 189
ISR 190
ISR 191
ISR 192
ISR 193
ISR 194
ISR 195
ISR 196
ISR 197
ISR 198
ISR 199
ISR 200
ISR 201
ISR 202
ISR 203
ISR 204
ISR 205
ISR 206
ISR 207
ISR 208
ISR 209
ISR 210
ISR 211
ISR 212
ISR 213
ISR 214
ISR 215
ISR 216
ISR 217
ISR 218
ISR 219
ISR 220
ISR 221
ISR 222
ISR 223
ISR 224
ISR 225
ISR 226
ISR 227
ISR 228
ISR 229
ISR 230
ISR 231
ISR 232
ISR 233
ISR 234
ISR 235
ISR 236
ISR 237
ISR 238
ISR 239
ISR 240
ISR 241
ISR 242
ISR 243
ISR 244
ISR 245
ISR 246
ISR 247
ISR 248
ISR 249
ISR 250
ISR 251
ISR 252
ISR 253
ISR 254
ISR 255
