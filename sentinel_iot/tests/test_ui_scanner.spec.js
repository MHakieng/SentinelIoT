import { test, expect } from '@playwright/test';

test('scanner loading state logic', async ({ page }) => {
  // 1. Dashboard'a git
  await page.goto('http://localhost:5173');
  
  // 2. 'Quick Scan' butonunu bul
  const scanBtn = page.getByRole('button', { name: /Quick Scan/i });
  await expect(scanBtn).toBeVisible();
  await expect(scanBtn).not.toBeDisabled();
  
  // 3. Taramayı başlat
  await scanBtn.click();
  
  // 4. Loading state'i doğrula
  // Buton metni 'Scanning...' olmalı ve disabled olmalı
  await expect(scanBtn).toHaveText(/Scanning.../i);
  await expect(scanBtn).toBeDisabled();
  
  // 5. Spinner ikonunun varlığını kontrol et
  const spinner = page.locator('.spin'); // Loader2 component has 'spin' class in our App.jsx
  await expect(spinner).toBeVisible();
  
  // 6. Tarama bitince eski haline dönmeli (Polling tamamlanınca)
  // Bu test için polling'in tamamlanmasını bekliyoruz
  await expect(scanBtn).toHaveText(/Quick Scan/i, { timeout: 60000 });
  await expect(scanBtn).not.toBeDisabled();
});
