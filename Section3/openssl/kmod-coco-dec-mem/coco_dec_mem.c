#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/mm_types.h>
#include <linux/mm.h>
#include <linux/types.h>
#include <asm/set_memory.h>
#include <linux/miscdevice.h>
#include <asm/io.h>
#include <linux/platform_device.h>
#include <linux/dma-mapping.h>
#include <linux/dma-direct.h>

MODULE_DESCRIPTION("Allows userspace to allocate unencrypted memory that can be read by the hypervisor");
MODULE_AUTHOR("Anon");
MODULE_LICENSE("GPL");


static struct platform_device *mem_pdev = NULL;

/* This stores a reference to the allocated memory. We need this to 
 * free the memory in. Currently this module requires you to free your previous
 * allocation before you can do a new allocation
*/
static void* allocated_mem = NULL;
static uint64_t allocated_mem_req_bytes = 0;

static void vma_open(struct vm_area_struct* vma) {
    printk("%s: virt %lx, phys %lx\n",
            __FUNCTION__, vma->vm_start, vma->vm_pgoff << PAGE_SHIFT);
}

static inline dma_addr_t virt_to_dma(void *vaddr) {
  return phys_to_dma(&mem_pdev->dev, virt_to_phys(vaddr));
}

static void free_allocated_mem(void) {
  if(!allocated_mem) {
    printk("%s: allocated_mem is NULL -> nothing to do\n", __FUNCTION__);
    return;
  }
  printk("%s: calling dma_free_attrs on 0x%llx\n", __FUNCTION__, (uint64_t)allocated_mem);
  dma_free_attrs(
                  &mem_pdev->dev,
                  allocated_mem_req_bytes,
                  (void*)allocated_mem,
                  virt_to_dma(allocated_mem),
                  DMA_ATTR_FORCE_CONTIGUOUS
                );

  
  allocated_mem = NULL;
  allocated_mem_req_bytes = 0;
}

static void vma_close(struct vm_area_struct* vma) {
  printk("%s: entering function\n", __FUNCTION__);
  free_allocated_mem();
}

static struct vm_operations_struct vm_ops = {
  .open = vma_open,
  .close = vma_close,
};






static int alloc_shared_mem(struct file * fp, struct vm_area_struct * vma) {
  uint8_t* kernel_shared_mem_vaddr;
  uint64_t kernel_shared_mem_gpa;
  uint64_t bytes;
  dma_addr_t handle;
  int idx,r;
  printk("%s: entering function\n", __FUNCTION__);

  bytes = vma->vm_end - vma->vm_start;
  printk("%s: requested size is: 0x%llx",__FUNCTION__, bytes);
  kernel_shared_mem_vaddr = dma_alloc_attrs(&mem_pdev->dev, bytes, &handle, GFP_KERNEL,  DMA_ATTR_FORCE_CONTIGUOUS );
  // kernel_shared_mem_vaddr = dma_direct_alloc(&mem_pdev->dev, bytes, &handle, GFP_KERNEL, DMA_ATTR_FORCE_CONTIGUOUS );
  if( !kernel_shared_mem_vaddr) {
    printk("%s: vmalloc_user failed\n", __FUNCTION__);
    return -ENOMEM;
  }
  printk("%s: kernel_shared_mem_vaddr=0x%llx\n",__FUNCTION__, (uint64_t) kernel_shared_mem_vaddr);
  VM_BUG_ON(virt_to_dma(kernel_shared_mem_vaddr) != handle);

  printk("Allocation spans %lld pages\n", bytes/PAGE_SIZE);
  for(idx=0; idx < bytes/PAGE_SIZE; idx++) {
    uint64_t gpa;
    uint8_t* vaddr;
    vaddr = kernel_shared_mem_vaddr + (idx * 4096);
    printk("%s: Getting gpa for vaddr 0x%llx\n", __FUNCTION__, (uint64_t)vaddr);
    gpa = virt_to_phys(vaddr);
    //store first page for use with remapping command
    if(idx == 0) {
      kernel_shared_mem_gpa = gpa;
    }
    printk("%s: page %d has gpa 0x%llx\n",__FUNCTION__, idx, gpa);
  }
  printk("gpa of first page 0x%llx\n", kernel_shared_mem_gpa);

  memset(kernel_shared_mem_vaddr, 0, bytes);
  printk("Mapping memory into userspace\n");
  // down_write(&current->mm->mmap_lock);
  // r = remap_pfn_range(vma, vma->vm_start, kernel_shared_mem_gpa >> PAGE_SHIFT, bytes/PAGE_SIZE, vma->vm_page_prot);
  r = vm_iomap_memory(vma, kernel_shared_mem_gpa, bytes);
  // up_write(&current->mm->mmap_lock);
  if( r ) {
    printk("%s: remap_pfn_range failed with %d\n", __FUNCTION__ ,r);
    return -EIO;
  }
  //save in global var to free this later on
  allocated_mem = kernel_shared_mem_vaddr;
  allocated_mem_req_bytes = bytes;

  vma->vm_ops = &vm_ops;
  printk("%s: leaving function\n", __FUNCTION__);
  return 0;  
}

static const struct file_operations coco_dec_mem_fops = {
  .owner = THIS_MODULE,
  .mmap = alloc_shared_mem,
};

static struct miscdevice misc_dev = {
  .name = KBUILD_MODNAME,
  .minor = MISC_DYNAMIC_MINOR,
  .fops = &coco_dec_mem_fops,
};

static struct platform_driver coco_dec_mem_driver = {
  .driver.name = KBUILD_MODNAME,
};

static int coco_dec_mem_init(void) {
  struct platform_device *pdev;
  int ret = 0;
  int need_pdev_unreg = 0;

  printk("Initializing %s module\n", KBUILD_MODNAME);

  //Initialize mem_pdev. We need this to get access to the dma allocation functions
  ret = platform_driver_register(&coco_dec_mem_driver);
  if(ret) {
    printk("%s platform_driver_register failed\n", __FUNCTION__);
    return ret;
  }
  need_pdev_unreg = 1;
  pdev = platform_device_register_simple(KBUILD_MODNAME, -1, NULL, 0);
  if(IS_ERR(pdev)) {
    printk("%s platform_device_register_simple failed\n", __FUNCTION__);
    ret = PTR_ERR(pdev);
    goto err_cleanup;
  }
  if(dma_set_coherent_mask(&pdev->dev, DMA_BIT_MASK(64))) {
    printk("%s dma_set_coherent_mask failed\n", __FUNCTION__);
    ret = -EIO;
    goto err_cleanup;
  }

  ret =misc_register(&misc_dev);
  if(ret) {
    printk("%s mic_register failed\n", __FUNCTION__ );
    goto err_cleanup;
  }

  
  mem_pdev = pdev;

  return ret;
err_cleanup:
  if(need_pdev_unreg) platform_driver_unregister(&coco_dec_mem_driver);
  if(mem_pdev) platform_device_unregister(mem_pdev);
  
  return ret;
}

static void coco_dec_mem_exit(void) {
  free_allocated_mem();
  printk("Removing %s\n", KBUILD_MODNAME);
  platform_device_unregister(mem_pdev);
  platform_driver_unregister(&coco_dec_mem_driver);
  misc_deregister(&misc_dev);

}


module_init(coco_dec_mem_init);
module_exit(coco_dec_mem_exit);

