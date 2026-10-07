from pathlib import Path

p = Path("src/main/java/registry/Registry.java")
s = p.read_text(encoding="utf-8")

old = '''            } catch (Exception e) {
                c.rollback();
                throw new RegistryException(2400, "Command failed: " + e.getMessage(), e);
            }'''

new = '''            } catch (Exception e) {
                c.rollback();
                e.printStackTrace();
                throw new RegistryException(2400, "Command failed: " + e.getMessage(), e);
            }'''

if old not in s:
    raise SystemExit("TARGET NOT FOUND")

p.write_text(s.replace(old, new, 1), encoding="utf-8")
print("DONE")