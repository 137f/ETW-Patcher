# 🚀 ETW-Patcher: Trampoline Evasion Toolkit (AMSI/ETW/Sysmon)

Bem-vindo ao **ETW-Patcher**! Esta é uma PoC (Proof of Concept) em C++ que utiliza a poderosa técnica de **Trampoline Hooking** para desativar ou verificar as funcionalidades de detecção mais comuns no Windows.

Especificamente, ela visa:
-   **AMSI** (Antimalware Scan Interface)
-   **ETW** (Event Tracing for Windows)
-   **NtTraceEvent** (comumente usado para monitoramento, como o Sysmon)

> ⚠️ **Disclaimer:** Esta ferramenta é estritamente para **fins de pesquisa** em segurança ofensiva e defesa. O uso em ambientes não autorizados é ilegal e antiético. Use com responsabilidade.

---

## 💡 Sobre o Trampoline Hooking

O Trampoline Hooking é uma técnica de *in-process hooking* onde a execução de uma função é desviada.

1.  O **prólogo** (os primeiros 12 bytes) da função alvo é copiado para uma **nova área de memória** alocada, o **Trampoline**.
2.  Um `JMP` de retorno é adicionado ao Trampoline, apontando para a instrução original logo após o patch.
3.  O início da função alvo é substituído por um **único `JMP`** de 5 bytes, redirecionando o fluxo de execução para o **Trampoline**.

**Nota sobre a Evasão:** No estado atual, o patch altera o alvo para sempre saltar para o Trampoline, o que **interrompe a execução normal da função alvo** (ex: `AmsiScanBuffer`), resultando em uma desativação da detecção.

---

## ✨ Comandos de Execução

Execute o `ETW-Patcher.exe` via linha de comando, passando o número do comando desejado:

| Comando | Descrição | Funções Alvo |
| :---: | :--- | :--- |
| **0** | **ALL** (Padrão) | Aplica o patch em **AMSI**, **ETW** e **NtTraceEvent** simultaneamente. |
| **1** | **AMSI** | Aplica o patch em `AmsiScanBuffer` (amsi.dll). |
| **2** | **ETW** | Aplica o patch em `EtwEventWrite` (ntdll.dll). |
| **3** | **SYSMON** | Aplica o patch em `NtTraceEvent` (ntdll.dll). |
| **4** | **CHECK** | Verifica se as funções acima estão com o patch aplicado. (Procura por `0xE9` - o opcode do JMP relativo - no primeiro byte). |

### Exemplo de Uso

```bash
# Patch de Evasão Completo
.\ETW-Patcher.exe 0

# Apenas Desativar o AMSI
.\ETW-Patcher.exe 1

# Apenas Desativar o ETW
.\ETW-Patcher.exe 2

# Apenas Desativar o NtTraceEvent ( Sysmon )
.\ETW-Patcher.exe 3

# Verificar o status (antes ou depois do patch)
.\ETW-Patcher.exe 4
```
---

## 🖼️ Imagens de exemplo  

![image](https://raw.githubusercontent.com/137f/ETW-Patcher/refs/heads/main/ETW-Patcher/Images/0.png)  
![image](https://raw.githubusercontent.com/137f/ETW-Patcher/refs/heads/main/ETW-Patcher/Images/1.png)  
![image](https://raw.githubusercontent.com/137f/ETW-Patcher/refs/heads/main/ETW-Patcher/Images/2.png)  
![image](https://raw.githubusercontent.com/137f/ETW-Patcher/refs/heads/main/ETW-Patcher/Images/3.png)  

---

## 💌 Contato

**Caso queira me contatar ou precise de algum serviço, me encontre nas seguintes plataformas:**

**Usuário do Discord: 4wj.**

**Instagram: @glowwz9**

**E-mail: vliyanie1337@proton.me**


