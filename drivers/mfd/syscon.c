// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * System Control Driver
 *
 * Copyright (C) 2012 Freescale Semiconductor, Inc.
 * Copyright (C) 2012 Linaro Ltd.
 *
 * Author: Dong Aisheng <dong.aisheng@linaro.org>
 */

#include <linux/cleanup.h>
#include <linux/clk.h>
#include <linux/err.h>
#include <linux/hwspinlock.h>
#include <linux/io.h>
#include <linux/init.h>
#include <linux/list.h>
#include <linux/mutex.h>
#include <linux/of.h>
#include <linux/of_address.h>
#include <linux/of_platform.h>
#include <linux/platform_data/syscon.h>
#include <linux/platform_device.h>
#include <linux/regmap.h>
#include <linux/reset.h>
#include <linux/mfd/syscon.h>
#include <linux/slab.h>
#include <trace/hooks/regmap.h>

static struct platform_driver syscon_driver;

static DEFINE_MUTEX(syscon_list_lock);
static LIST_HEAD(syscon_list);

struct syscon {
	struct device_node *np;
	struct regmap *regmap;
	struct reset_control *reset;
	struct list_head list;
};

static const struct regmap_config syscon_regmap_config = {
	.reg_bits = 32,
	.val_bits = 32,
	.reg_stride = 4,
};

static struct syscon *of_syscon_register(struct device_node *np, bool check_res)
{
	struct clk *clk;
	struct regmap *regmap;
	void __iomem *base;
	u32 reg_io_width;
	int ret;
	struct regmap_config syscon_config = syscon_regmap_config;
	struct resource res;
	struct reset_control *reset;

	WARN_ON(!mutex_is_locked(&syscon_list_lock));

	struct syscon *syscon __free(kfree) = kzalloc(sizeof(*syscon), GFP_KERNEL);
	if (!syscon)
		return ERR_PTR(-ENOMEM);

	if (of_address_to_resource(np, 0, &res))
		return ERR_PTR(-ENOMEM);

	base = of_iomap(np, 0);
	if (!base)
		return ERR_PTR(-ENOMEM);

	/* Parse the device's DT node for an endianness specification */
	if (of_property_read_bool(np, "big-endian"))
		syscon_config.val_format_endian = REGMAP_ENDIAN_BIG;
	else if (of_property_read_bool(np, "little-endian"))
		syscon_config.val_format_endian = REGMAP_ENDIAN_LITTLE;
	else if (of_property_read_bool(np, "native-endian"))
		syscon_config.val_format_endian = REGMAP_ENDIAN_NATIVE;

	/*
	 * search for reg-io-width property in DT. If it is not provided,
	 * default to 4 bytes. regmap_init_mmio will return an error if values
	 * are invalid so there is no need to check them here.
	 */
	ret = of_property_read_u32(np, "reg-io-width", &reg_io_width);
	if (ret)
		reg_io_width = 4;

	ret = of_hwspin_lock_get_id(np, 0);
	if (ret > 0 || (IS_ENABLED(CONFIG_HWSPINLOCK) && ret == 0)) {
		syscon_config.use_hwlock = true;
		syscon_config.hwlock_id = ret;
		syscon_config.hwlock_mode = HWLOCK_IRQSTATE;
	} else if (ret < 0) {
		switch (ret) {
		case -ENOENT:
			/* Ignore missing hwlock, it's optional. */
			break;
		default:
			pr_err("Failed to retrieve valid hwlock: %d\n", ret);
			fallthrough;
		case -EPROBE_DEFER:
			goto err_regmap;
		}
	}

	syscon_config.name = kasprintf(GFP_KERNEL, "%pOFn@%pa", np, &res.start);
	if (!syscon_config.name) {
		ret = -ENOMEM;
		goto err_regmap;
	}
	syscon_config.reg_stride = reg_io_width;
	syscon_config.val_bits = reg_io_width * 8;
	syscon_config.max_register = resource_size(&res) - reg_io_width;

	regmap = regmap_init_mmio(NULL, base, &syscon_config);
	kfree(syscon_config.name);
	if (IS_ERR(regmap)) {
		pr_err("regmap init failed\n");
		ret = PTR_ERR(regmap);
		goto err_regmap;
	}

	if (check_res) {
		clk = of_clk_get(np, 0);
		if (IS_ERR(clk)) {
			ret = PTR_ERR(clk);
			/* clock is optional */
			if (ret != -ENOENT)
				goto err_clk;
		} else {
			ret = regmap_mmio_attach_clk(regmap, clk);
			if (ret)
				goto err_attach_clk;
		}

		reset = of_reset_control_get_optional_exclusive(np, NULL);
		if (IS_ERR(reset)) {
			ret = PTR_ERR(reset);
			goto err_attach_clk;
		}

		ret = reset_control_deassert(reset);
		if (ret)
			goto err_reset;
	}

	trace_android_vh_regmap_update(&syscon_config, regmap);
	syscon->regmap = regmap;
	syscon->np = np;

	list_add_tail(&syscon->list, &syscon_list);

	return_ptr(syscon);

err_reset:
	reset_control_put(reset);
err_attach_clk:
	if (!IS_ERR(clk))
		clk_put(clk);
err_clk:
	regmap_exit(regmap);
err_regmap:
	iounmap(base);
	return ERR_PTR(ret);
}

static struct regmap *device_node_get_regmap(struct device_node *np,
					     bool check_res)
{
	struct syscon *entry, *syscon = NULL;

	mutex_lock(&syscon_list_lock);

	list_for_each_entry(entry, &syscon_list, list)
		if (entry->np == np) {
			syscon = entry;
			break;
		}

	if (!syscon)
		syscon = of_syscon_register(np, check_res);

	mutex_unlock(&syscon_list_lock);

	if (IS_ERR(syscon))
		return ERR_CAST(syscon);

	return syscon->regmap;
}

/**
 * of_syscon_register_regmap() - Register regmap for specified device node
 * @np: Device tree node
 * @regmap: Pointer to regmap object
 *
 * Register an externally created regmap object with syscon for the specified
 * device tree node. This regmap will then be returned to client drivers using
 * the syscon_regmap_lookup_by_phandle() API.
 *
 * Return: 0 on success, negative error code on failure.
 */
int of_syscon_register_regmap(struct device_node *np, struct regmap *regmap)
{
	struct syscon *entry, *syscon = NULL;
	int ret;

	if (!np || !regmap)
		return -EINVAL;

	syscon = kzalloc(sizeof(*syscon), GFP_KERNEL);
	if (!syscon)
		return -ENOMEM;

	/* check if syscon entry already exists */
	mutex_lock(&syscon_list_lock);

	list_for_each_entry(entry, &syscon_list, list)
		if (entry->np == np) {
			ret = -EEXIST;
			goto err_unlock;
		}

	syscon->regmap = regmap;
	syscon->np = np;

	/* register the regmap in syscon list */
	list_add_tail(&syscon->list, &syscon_list);
	mutex_unlock(&syscon_list_lock);

	return 0;

err_unlock:
	mutex_unlock(&syscon_list_lock);
	kfree(syscon);
	return ret;
}
EXPORT_SYMBOL_GPL(of_syscon_register_regmap);

struct regmap *device_node_to_regmap(struct device_node *np)
{
	return device_node_get_regmap(np, false);
}
EXPORT_SYMBOL_GPL(device_node_to_regmap);

struct regmap *syscon_node_to_regmap(struct device_node *np)
{
	if (!of_device_is_compatible(np, "syscon"))
		return ERR_PTR(-EINVAL);

	return device_node_get_regmap(np, true);
}
EXPORT_SYMBOL_GPL(syscon_node_to_regmap);

struct regmap *syscon_regmap_lookup_by_compatible(const char *s)
{
	struct device_node *syscon_np;
	struct regmap *regmap;

	syscon_np = of_find_compatible_node(NULL, NULL, s);
	if (!syscon_np)
		return ERR_PTR(-ENODEV);

	regmap = syscon_node_to_regmap(syscon_np);
	of_node_put(syscon_np);

	return regmap;
}
EXPORT_SYMBOL_GPL(syscon_regmap_lookup_by_compatible);

struct regmap *syscon_regmap_lookup_by_phandle(struct device_node *np,
					const char *property)
{
	struct device_node *syscon_np;
	struct regmap *regmap;

	if (property)
		syscon_np = of_parse_phandle(np, property, 0);
	else
		syscon_np = np;

	if (!syscon_np)
		return ERR_PTR(-ENODEV);

	regmap = syscon_node_to_regmap(syscon_np);

	if (property)
		of_node_put(syscon_np);

	return regmap;
}
EXPORT_SYMBOL_GPL(syscon_regmap_lookup_by_phandle);

struct regmap *syscon_regmap_lookup_by_phandle_args(struct device_node *np,
					const char *property,
					int arg_count,
					unsigned int *out_args)
{
	struct device_node *syscon_np;
	struct of_phandle_args args;
	struct regmap *regmap;
	unsigned int index;
	int rc;

	rc = of_parse_phandle_with_fixed_args(np, property, arg_count,
			0, &args);
	if (rc)
		return ERR_PTR(rc);

	syscon_np = args.np;
	if (!syscon_np)
		return ERR_PTR(-ENODEV);

	regmap = syscon_node_to_regmap(syscon_np);
	for (index = 0; index < arg_count; index++)
		out_args[index] = args.args[index];
	of_node_put(syscon_np);

	return regmap;
}
EXPORT_SYMBOL_GPL(syscon_regmap_lookup_by_phandle_args);

/*
 * It behaves the same as syscon_regmap_lookup_by_phandle() except where
 * there is no regmap phandle. In this case, instead of returning -ENODEV,
 * the function returns NULL.
 */
struct regmap *syscon_regmap_lookup_by_phandle_optional(struct device_node *np,
					const char *property)
{
	struct regmap *regmap;

	regmap = syscon_regmap_lookup_by_phandle(np, property);
	if (IS_ERR(regmap) && PTR_ERR(regmap) == -ENODEV)
		return NULL;

	return regmap;
}
EXPORT_SYMBOL_GPL(syscon_regmap_lookup_by_phandle_optional);

static int syscon_probe(struct platform_device *pdev)
{
	struct device *dev = &pdev->dev;
	struct syscon_platform_data *pdata = dev_get_platdata(dev);
	struct syscon *syscon;
	struct regmap_config syscon_config = syscon_regmap_config;
	struct resource *res;
	void __iomem *base;

	syscon = devm_kzalloc(dev, sizeof(*syscon), GFP_KERNEL);
	if (!syscon)
		return -ENOMEM;

	res = platform_get_resource(pdev, IORESOURCE_MEM, 0);
	if (!res)
		return -ENOENT;

	base = devm_ioremap(dev, res->start, resource_size(res));
	if (!base)
		return -ENOMEM;

	syscon_config.max_register = resource_size(res) - 4;
	if (pdata)
		syscon_config.name = pdata->label;
	syscon->regmap = devm_regmap_init_mmio(dev, base, &syscon_config);
	if (IS_ERR(syscon->regmap)) {
		dev_err(dev, "regmap init failed\n");
		return PTR_ERR(syscon->regmap);
	}

	platform_set_drvdata(pdev, syscon);

	dev_dbg(dev, "regmap %pR registered\n", res);

	return 0;
}

static const struct platform_device_id syscon_ids[] = {
	{ "syscon", },
	{ }
};

static struct platform_driver syscon_driver = {
	.driver = {
		.name = "syscon",
	},
	.probe		= syscon_probe,
	.id_table	= syscon_ids,
};

static int __init syscon_init(void)
{
	return platform_driver_register(&syscon_driver);
}
postcore_initcall(syscon_init);
