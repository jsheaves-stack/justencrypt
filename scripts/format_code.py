import os

def process_file(filepath):
    with open(filepath, 'r') as f:
        lines = f.read().split('\n')
    
    new_lines = []
    
    for i in range(len(lines)):
        line = lines[i]
        stripped = line.strip()
        
        if len(new_lines) > 0:
            prev_line = new_lines[-1]
            prev_stripped = prev_line.strip()
            
            if stripped != '' and prev_stripped != '':
                needs_blank = False
                
                # Rule 1: Blank line before return
                if stripped.startswith('return ') and not prev_stripped.endswith('{') and prev_stripped != '}':
                    needs_blank = True
                    
                # Rule 2: Blank line before if, if let, match
                if (stripped.startswith('if ') or stripped.startswith('match ') or ' match ' in stripped) \
                   and not prev_stripped.endswith('{') and prev_stripped != '}' and not prev_stripped.endswith('('):
                    if not stripped.startswith('} else') and not stripped.startswith('else if'):
                        needs_blank = True
                        
                # Rule 3: Blank line after logging macros
                if prev_stripped.endswith(');') and any(m in prev_stripped for m in ['error!(', 'warn!(', 'info!(', 'trace!(', 'debug!(']):
                    if not stripped.startswith('return ') and not stripped.startswith('}'):
                        needs_blank = True
                        
                # Rule 4: Blank line before let if previous line ended a block
                if stripped.startswith('let ') and prev_stripped == '}':
                    needs_blank = True
                    
                # Rule 5: Blank line before Ok(...) or Err(...) at end of block
                if (stripped.startswith('Ok(') or stripped.startswith('Err(') or stripped == 'Ok(())' or stripped == 'Err(())'):
                    if i < len(lines) - 1 and lines[i+1].strip() == '}':
                        if not prev_stripped.endswith('{') and prev_stripped != '}':
                            needs_blank = True
                
                if needs_blank:
                    new_lines.append('')
        
        new_lines.append(line)
        
    with open(filepath, 'w') as f:
        f.write('\n'.join(new_lines))

for root, _, files in os.walk('src'):
    for f in files:
        if f.endswith('.rs'):
            process_file(os.path.join(root, f))
